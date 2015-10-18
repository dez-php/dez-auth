<?php

    namespace Auth;

    use Dez\Auth\Adapter\Session;
    use Dez\Auth\Adapter\Token;
    use Dez\Auth\Auth;
    use Dez\Auth\Manager;
    use Dez\Config\Adapter\Json;
    use Dez\DependencyInjection\Container;
    use Dez\Http\Cookies;
    use Dez\Http\Request;
    use Dez\ORM\Connection;
    use Dez\Session\Adapter\Files;

    error_reporting(1);
    ini_set('display_errors', 'On');

    include_once '../vendor/autoload.php';

    ////// init //////
    Connection::init( new Json( 'config/connection.json' ), 'dev' );

    $di = Container::instance();

    $queries        = [];

    \Dez\ORM\Common\Event::instance()->attach( 'query', function( $query ) use ( & $queries ) {
        $queries[]  = $query;
    } );

    $di->set( 'request', new Request() );
    $di->set( 'session', new Files() );
    $di->set( 'cookies', new Cookies() );

    $di->set( 'auth', new Auth( new Session( $di ) ) );

    $di->set( 'auth_token', new Auth( new Token( $di ) ) );
    //////////////////

    $email      = 'qwerty@mail.com';
    $password   = 'qwerty';

    /** @var $auth Auth */
    $auth       = $di->get('auth');
    $apiAuth    = $di->get('auth_token');

//    $auth->create($email, $password); die;

//    $auth->authenticate( $email, $password );

    $apiAuth->identifyToken( '32258333-bb11-4abf-919c-03fb01810cea' );

    var_dump(
        $apiAuth->user()->getEmail(),
//        $apiAuth->generateToken($email, $password),
        $auth->user()->getEmail(), $queries
    );


