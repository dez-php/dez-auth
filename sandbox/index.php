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

    error_reporting(1); ini_set('display_errors', 1);

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
    //////////////////

    $email      = 'stewie@mail.com';
    $password   = 'qwerty';

    /** @var $auth Auth */
    $auth    = $di->get('auth');

    $auth->authenticate( $email, $password );

    $di->get('cookies')->send();
    var_dump( $auth->getAdapter(), $queries );


