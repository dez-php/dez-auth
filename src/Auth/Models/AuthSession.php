<?php

    namespace Dez\Auth\Models;

    use Dez\ORM\Model\Table as ORMTable;

    /**
     * Class AuthSession
     * @package Dez\Auth\Models
     */
    class AuthSession extends ORMTable {

        /**
         * @var string
         */
        static protected $table = 'auth_sessions';

    }