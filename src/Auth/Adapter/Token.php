<?php

    namespace Dez\Auth\Adapter;

    use Dez\Auth\Adapter;
    use Dez\Auth\InvalidDataException;
    use Dez\Auth\Models\Auth\TokenModel;
    use Dez\Auth\NotFoundException;
    use Dez\DependencyInjection\ContainerInterface;

    /**
     * Class Token
     * @package Dez\Auth\Adapter
     */
    class Token extends Adapter {

        /**
         * @var
         */
        protected $token;

        /**
         * @param ContainerInterface $di
         */
        public function __construct( ContainerInterface $di ) {
            $this->setDi( $di );
        }

        /**
         * @return $this
         */
        public function initialize() {
            return $this;
        }

        /**
         * @return $this
         * @throws NotFoundException
         */
        public function authenticate() {

            $tokenModel = TokenModel::query()
                ->where( 'token', $this->getToken() )
                ->first();

            if( $tokenModel->exists() ) {
                $credential = $tokenModel->credentials();
                if( ! $credential->exists() ) {
                    throw new NotFoundException( "Credentials for token: {$this->getToken()} broken" );
                }
                $this->getAuth()->setModel( $credential );
            } else {
                throw new NotFoundException( 'Token was wrong or not exists' );
            }

            return $this;
        }

        /**
         * @return mixed
         */
        public function getToken() {
            return $this->token;
        }

        /**
         * @param mixed $token
         * @return $this
         */
        public function setToken( $token ) {
            $this->token = $token;
            return $this;
        }

        /**
         * @return mixed
         * @throws InvalidDataException
         * @throws \Dez\Auth\AuthException
         * @throws \Dez\Auth\InvalidPasswordException
         */
        public function generateToken() {

            if( ! $this->getEmail() || ! $this->getPassword() ) {
                throw new InvalidDataException( 'Set before email and password' );
            }

            $credentialModel    = $this->checkCredential();
            $tokenModel         = TokenModel::query()
                ->where( 'unique_hash', $this->getUniqueHash() )
                ->first();

            $randomHash         = $this->getRandomHash();

            $tokenModel->set( 'token', $randomHash );
            $tokenModel->set( 'expiry_date', ( new \DateTime( '+30 days' ) )->format( 'Y-m-d H:i:s' ) );
            $tokenModel->set( 'used_at', ( new \DateTime() )->format( 'Y-m-d H:i:s' ) );
            $tokenModel->set( 'auth_id', $credentialModel->id() );

            if( ! $tokenModel->exists() ) {
                $tokenModel->set( 'unique_hash', $this->getUniqueHash() );
                $tokenModel->set( 'created_at', ( new \DateTime() )->format( 'Y-m-d H:i:s' ) );
            }

            $tokenModel->save();

            return $tokenModel->getToken();
        }

        /**
         * @return $this
         */
        public function logout() {
            TokenModel::query()
                ->where( 'token', $this->getToken() )
                ->delete();
            return $this;
        }

        /**
         * @return $this
         */
        public function cleanTokens() {
            TokenModel::query()
                ->where( 'expiry_date', ( new \DateTime() )->format( 'Y-m-d H:i:s' ), '<=' )
                ->delete();
            return $this;
        }

    }