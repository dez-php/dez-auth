<?php

    namespace Dez\Auth;

    use Dez\Auth\Adapter\Session;
    use Dez\Auth\Models\CredentialModel;
    use Dez\DependencyInjection\Container;

    /**
     * Class Auth
     * @package Dez\Auth
     */
    class Auth {

        /**
         * @var Adapter
         */
        protected $adapter;

        /**
         * @var CredentialModel
         */
        protected $model;

        /**
         * @param Adapter $adapter
         */
        public function __construct( Adapter $adapter ) {
            $this->setAdapter( $adapter->setAuth( $this )->initialize() );
        }

        /**
         * @param $email
         * @param $password
         * @return $this
         */
        public function authenticate( $email, $password ) {
            $this->getAdapter()
                ->setEmail( $email )
                ->setPassword( $password )
                ->authenticate();
            return $this;
        }

        /**
         * @param $token
         * @return $this
         */
        public function identifyToken( $token ) {
            $this->getAdapter()->setToken( $token )->authenticate();
            return $this;
        }

        /**
         * @param $email
         * @param $password
         * @return mixed
         */
        public function generateToken( $email, $password ) {
            return $this->getAdapter()
                ->setEmail( $email )
                ->setPassword( $password )
                ->generateToken();
        }

        /**
         * @param $email
         * @param $password
         * @return $this
         */
        public function create( $email, $password ) {
            $model      = new CredentialModel();

            $dateToday  = ( new \DateTime() )->format( 'Y-m-d H:i:s' );

            $model
                ->setEmail( $email )
                ->setPassword( $this->getAdapter()->hashPassword( $password ) )
                ->setStatus( Session::STATUS_ACTIVE )
                ->setCreatedAt( $dateToday )
                ->setUpdatedAt( $dateToday );

            $model->save();

            $this->setModel( $model );

            return $this;
        }

        /**
         * @return Adapter
         */
        public function getAdapter() {
            return $this->adapter;
        }

        /**
         * @param Adapter $adapter
         * @return $this
         */
        public function setAdapter( Adapter $adapter ) {
            $this->adapter = $adapter;
            return $this;
        }

        /**
         * @return CredentialModel
         */
        public function getModel() {
            return $this->model;
        }

        /**
         * @param CredentialModel $model
         * @return $this
         */
        public function setModel( CredentialModel $model ) {
            $this->model = $model;
            return $this;
        }

        /**
         * @return bool
         */
        public function isGuest() {
            return ( $this->getModel()->exists() === false );
        }

        /**
         * @return bool
         */
        public function isUser() {
            return ( $this->getModel()->exists() !== false && $this->getModel()->id() > 0 );
        }

        /**
         * @return CredentialModel
         */
        public function user() {
            return $this->getModel();
        }

        /**
         * @param $authId
         * @return $this
         */
        public function forceLogin( $authId ) {

            $authModel  = CredentialModel::one( $authId );

            if( $authModel->exists() ) {
                $this->setModel( $authModel );
                $this->setAdapter( new Session( Container::instance() ) );
                $this->setAdapter()->makeSession();
            }

            return $this;
        }

    }