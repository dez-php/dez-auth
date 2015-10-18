<?php

    namespace Dez\Auth\Adapter;

    use Dez\Auth\Adapter;
    use Dez\Auth\AuthException;
    use Dez\Auth\Models\Auth\SessionModel;
    use Dez\Auth\Models\CredentialModel;
    use Dez\DependencyInjection\ContainerInterface;

    /**
     * Class Credentials
     * @package Dez\Auth\Adapter
     */
    class Session extends Adapter {

        const COOKIE_KEY    = 'dez-auth-key';

        /**
         * @var string
         */
        protected $email;

        /**
         * @var string
         */
        protected $password;

        /**
         * @param ContainerInterface $di
         */
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
         * @throws \Exception
         */
        public function authenticate() {
            $this->checkCredential();
            $this->makeSession();
            return $this;
        }

        /**
         * @return $this
         * @throws AuthException
         */
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
                $sessionModel->set( 'created_at', ( new \DateTime() )->format( 'Y-m-d H:i:s' ) );
            }

            $cookies    = $this->getCookies();
            $expire     = time() + ( 86400 * 30 );
            $cookies->set( $this->getCookieAuthKey(), $randomHash, $expire, '/' );

            $cookies->send();

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

        /**
         * @return string
         */
        public function getCookieAuthKey() {
            return self::COOKIE_KEY . '_' . $this->getUniqueHash();
        }

    }