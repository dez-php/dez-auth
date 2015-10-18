<?php

    namespace Dez\Auth\Models\Auth;

    use Dez\Auth\Models\CredentialModel;
    use Dez\ORM\Model\Table as ORMTable;

    /**
     * Class AuthSession
     * @package Dez\Auth\Models
     */
    class TokenModel extends ORMTable {

        /**
         * @var string
         */
        static protected $table = 'auth_tokens';

        /**
         * @return mixed
         * @throws \Dez\ORM\Exception
         */
        public function credentials() {
            return $this->hasOne( CredentialModel::class, 'id', 'auth_id' );
        }

    }