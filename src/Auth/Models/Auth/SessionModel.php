<?php

    namespace Dez\Auth\Models\Auth;

    use Dez\Auth\Models\CredentialModel;
    use Dez\ORM\Model\Table as ORMTable;

    /**
     * Class AuthSession
     * @package Dez\Auth\Models
     */
    class SessionModel extends ORMTable {

        /**
         * @var string
         */
        static protected $table = 'auth_sessions';

        public function credentials() {
            return $this->hasOne( CredentialModel::class, 'id', 'auth_id' );
        }

    }