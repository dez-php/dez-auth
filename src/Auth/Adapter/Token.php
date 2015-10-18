<?php

    namespace Dez\Auth\Adapter;

    use Dez\Auth\Adapter;
    use Dez\Auth\Hasher\UUID;
    use Dez\Auth\Models\Auth\Token as TokenModel;
    use Dez\Auth\NotFoundException;

    /**
     * Class Token
     * @package Dez\Auth\Adapter
     */
    class Token extends Adapter {

        protected $token;

        protected $auth_id  = 0;

        public function __construct( $token ) {
            $this->setToken( $token );
        }

        public function authenticate() {

            $tokenModel = TokenModel::query()
                ->where( 'token', $this->getToken() )
                ->where( 'unique_hash', $this->getManager()->getUniqueHash() )
                ->first();

            if( $tokenModel->exists() ) {

                $credential = $tokenModel->credential();

                if( ! $credential->exists() ) {
                    throw new NotFoundException( 'Token exist, but credentials broken' );
                }

                $this->getManager()->setModel( $tokenModel->credential() );

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
         * @return int
         */
        public function getAuthId() {
            return $this->auth_id;
        }

        /**
         * @param int $auth_id
         * @return $this
         */
        public function setAuthId( $auth_id ) {
            $this->auth_id = $auth_id;
            return $this;
        }

        public function create() {

            $model  = new TokenModel();

            $model
                ->setAuthId( $this->getAuthId() )
                ->setToken( $this->getToken() )
                ->setUniqueHash( $this->getManager()->getUniqueHash() )
                ->setExpiryDate( ( new \DateTime( '+30 days' ) )->format( 'Y-m-d H:i:s' ) )
                ->setCreatedAt( ( new \DateTime() )->format( 'Y-m-d H:i:s' ) )
                ->setUpdatedAt( ( new \DateTime() )->format( 'Y-m-d H:i:s' ) )
            ->save();

            $this->getManager()->setModel( $model );
            $this->setToken( $model->getToken() );

            return $model->getToken();

        }

    }