<?php

    namespace Dez\Auth;

    use Dez\Auth\Hasher\UUID;
    use Dez\DependencyInjection\ContainerInterface;
    use Dez\DependencyInjection\InjectableInterface;
    use Dez\Http\CookiesInterface;
    use Dez\Http\RequestInterface;
    use Dez\Session\AdapterInterface;

    abstract class Adapter implements InjectableInterface {

        const SALT = '$|AUjz$guB1HwH627l?gl&pB3fS8$KBD';

        /**
         * @var ContainerInterface
         */
        protected $dependencyInjection;

        /**
         * @var Auth
         */
        protected $auth;

        /**
         * @return ContainerInterface
         */
        public function getDi() {
            return $this->dependencyInjection;
        }

        /**
         * @param ContainerInterface $dependencyInjector
         * @return $this
         */
        public function setDi( ContainerInterface $dependencyInjector ) {
            $this->dependencyInjection = $dependencyInjector;
            return $this;
        }

        /**
         * @return Auth
         */
        public function getAuth() {
            return $this->auth;
        }

        /**
         * @param mixed $auth
         * @return $this
         */
        public function setAuth( Auth $auth ) {
            $this->auth = $auth;
            return $this;
        }

        /**
         * @return CookiesInterface
         * @throws AuthException
         */
        public function getCookies() {
            if( ! $this->getDi() ) {
                throw new AuthException( 'Dependency Injection require for AuthAdapter' );
            }

            if( ! $this->getDi()->has( 'cookies' ) ) {
                throw new AuthException( 'Cookies require for AuthAdapter' );
            }

            return $this->getDi()->get( 'cookies' );
        }

        /**
         * @return AdapterInterface
         * @throws AuthException
         */
        public function getSession() {
            if( ! $this->getDi() ) {
                throw new AuthException( 'Dependency Injection require for AuthAdapter' );
            }

            if( ! $this->getDi()->has( 'session' ) ) {
                throw new AuthException( 'Session require for AuthAdapter' );
            }

            return $this->getDi()->get( 'session' );
        }

        /**
         * @return RequestInterface
         * @throws AuthException
         */
        public function getRequest() {
            if( ! $this->getDi() ) {
                throw new AuthException( 'Dependency Injection require for AuthManager' );
            }

            if( ! $this->getDi()->has( 'request' ) ) {
                throw new AuthException( 'Request require for AuthManager' );
            }

            return $this->getDi()->get( 'request' );
        }

        /**
         * @param string $rawPassword
         * @return string
         */
        public function hashPassword( $rawPassword = '' ) {
            return UUID::v5( $rawPassword . self::SALT );
        }

        /**
         * @param $hash
         * @param $password
         * @return bool
         */
        public function verifyPassword( $hash, $password ) {
            return $this->hashPassword( $password ) === $hash;
        }

        /**
         * @return string
         * @throws AuthException
         */
        public function getUniqueHash() {
            return UUID::v5(
                $this->getRequest()->getRealClientIP() .
                $this->getRequest()->getUserAgent()
            );
        }

        /**
         * @return string
         */
        public function getRandomHash() {
            return UUID::v4();
        }


        /**
         * @param string $authKey
         * @return string
         */
        public function createSecureHash( $authKey = '' ) {
            return UUID::v5( $authKey . $this->getUniqueHash() );
        }

        /**
         * @return mixed
         */
        abstract public function authenticate();

        abstract public function initialize();

    }