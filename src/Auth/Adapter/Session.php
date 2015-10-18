<?php

    namespace Dez\Auth\Adapter;

    use Dez\Auth\Adapter;
    use Dez\Auth\AuthException;
    use Dez\Auth\InvalidPasswordException;
    use Dez\Auth\Models\Auth\SessionModel;
    use Dez\Auth\Models\CredentialModel;
    use Dez\DependencyInjection\ContainerInterface;

    /**
     * Class Credentials
     * @package Dez\Auth\Adapter
     */
    class Session extends Adapter {

        const COOKIE_KEY    = 'dez-auth-key';

        const STATUS_ACTIVE = 'active';

        protected $email;

        protected $password;

        public function __construct( ContainerInterface $di ) {
            $this->setDi( $di );
            $this->cleanSessions();
        }

        /**
         * @return $this
         * @throws \Dez\Auth\AuthException
         */
        public function initialize() {
            $this->getAuth()->setModel( new CredentialModel() );

            $key        = $this->getCookieAuthKey();
            $cookies    = $this->getCookies();

            if( $authKey = $cookies->get( $key, false ) ) {
                $sessionModel   = $this->findSessionModel( $this->createSecureHash( $authKey ) );
                if( $sessionModel->exists() ) {
                    $this->getAuth()->setModel( $sessionModel->credentials() );
                }
            }

            return $this;
        }

        /**
         * @return $this
         * @throws AuthException
         * @throws InvalidPasswordException
         */
        public function authenticate() {

            $model  = CredentialModel::query()
                ->where( 'email', $this->getEmail() )
                ->where( 'password', $this->hashPassword( $this->getPassword() ) )
                ->first();

            if( $model->exists() ) {
                if( $model->get( 'status' ) == self::STATUS_ACTIVE ) {
                    $this->getAuth()->setModel( $model );
                    $this->makeSession();
                } else {
                    throw new AuthException( 'Account was blocked' );
                }
            } else {
                throw new InvalidPasswordException( 'Invalid email or password' );
            }

            return $this;
        }

        /**
         * @return mixed
         */
        public function getEmail() {
            return $this->email;
        }

        /**
         * @param mixed $email
         * @return $this
         */
        public function setEmail( $email ) {
            $this->email = $email;
            return $this;
        }

        /**
         * @return mixed
         */
        public function getPassword() {
            return $this->password;
        }

        /**
         * @param mixed $password
         * @return $this
         */
        public function setPassword( $password ) {
            $this->password = $password;
            return $this;
        }

        public function makeSession() {
            $randomHash         = $this->getRandomHash();

            $credentialModel    = $this->getAuth()->getModel();
            $sessionModel       = SessionModel::query()
                ->where( 'auth_id', $credentialModel->id() )
                ->where( 'unique_hash', $this->getUniqueHash() )
                ->first();

            $sessionModel->set( 'auth_hash', $this->createSecureHash( $randomHash ) );
            $sessionModel->set( 'expiry_date', ( new \DateTime( '+30 days' ) )->format( 'Y-m-d H:i:s' ) );
            $sessionModel->set( 'used_at', ( new \DateTime() )->format( 'Y-m-d H:i:s' ) );

            if( ! $sessionModel->exists() ) {
                $sessionModel->set( 'auth_id', $credentialModel->id() );
                $sessionModel->set( 'unique_hash', $this->getUniqueHash() );
                $sessionModel->set( 'created_at', ( new \DateTime( '+30 days' ) )->format( 'Y-m-d H:i:s' ) );
            }

            $this->getCookies()->set( $this->getCookieAuthKey(), $randomHash, time() + 86400 * 30 )->send();

            $sessionModel->save();

            return $this;
        }

        /**
         * @param $uniqueHash
         * @return \Dez\ORM\Model\Table
         */
        public function findSessionModel( $uniqueHash ) {
            $model  = SessionModel::query()
                ->where( 'auth_hash', $uniqueHash )
                ->where( 'expiry_date', ( new \DateTime() )->format( 'Y-m-d H:i:s' ), '>' )
                ->first();
            return $model;
        }

        /**
         * @return $this
         */
        public function cleanSessions() {
            SessionModel::query()
                ->where( 'expiry_date', ( new \DateTime() )->format( 'Y-m-d H:i:s' ), '<=' )
                ->delete();
            return $this;
        }

        public function getCookieAuthKey() {
            return self::COOKIE_KEY . '_' . $this->getUniqueHash();
        }

    }