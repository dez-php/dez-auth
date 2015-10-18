<?php

    namespace Dez\Auth\Models;

    use Dez\Auth\Models\Auth\SessionModel;
    use Dez\Auth\Models\Auth\TokenModel;
    use Dez\ORM\Model\Table as ORMTable;

    /**
     * Class AuthSession
     * @package Dez\Auth\Models
     */
    class CredentialModel extends ORMTable {

        /**
         * @var string
         */
        static protected $table = 'auth_credentials';

        /**
         * @return mixed
         * @throws \Dez\ORM\Exception
         */
        public function tokens() {
            return $this->hasMany( TokenModel::class, 'auth_id' );
        }

        /**
         * @return mixed
         * @throws \Dez\ORM\Exception
         */
        public function sessions() {
            return $this->hasMany( SessionModel::class, 'auth_id' );
        }

    }