<?php

    require_once __DIR__ . '/utils.php';

    /* Avoid direct page request */
    exitIfRequested(__FILE__);

    /* DB Singleton */
    /* Singleton has been used to get a common shared DB connection */
    class DB{

        private static $instance = null;
        private $connection = null;

        private $hostname = null;
        private $dbname = null;
        private $username = null;
        private $password = null;

        /*
         * Get db shared instance
         */
        public static function getInstance(){
            //If no PDO instance has been created
            if(static::$instance === null){
                //Create it
                static::$instance = new DB();
            }

            //Return shared DB connection
            return static::$instance;
        }

        private function __construct(){
            try{

                $this->hostname = $_ENV['MYSQL_HOST'];
                $this->dbname = $_ENV['MYSQL_DATABASE'];
                $this->username = 'root';
                $this->password = $_ENV['MYSQL_ROOT_PASSWORD'];

                //Make DB connection
                $this->connection = new PDO("mysql:host={$this->hostname};dbname={$this->dbname};charset=utf8mb4", $this->username, $this->password);
                //Set error mode to exception
                $this->connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
                $this->connection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            }
            catch(PDOException $e){
                print($e);
                http_response_code(BAD_REQUEST);
                die();
            }
        }

        public function __destruct(){
            //Close db connection on destruction
            $this->connection = null;
            static::$instance = null;
        }

        /*
         * Executes single query statement:
         * with or without parameters
         * with or without result set
         */
        public function exec($query, $values = []){
            //Make prepared statement
            $prepared = $this->connection->prepare($query);
            //Execute prepared query with or without parameters
            $prepared->execute($values);

            try{
                //Attempt to fetch result set as associative aray
                $result = $prepared->fetchAll(PDO::FETCH_ASSOC);
            }
            catch(PDOException $e){
                //If no result set is found return true if rows have been affected
                return ($prepared->rowCount() > 0);
            }

            //If there is a result set return it
            return $result;
        }

        public function lastInsertId(){
            return $this->connection->lastInsertId();
        }

        /* Avoid object clonation */
        private function __clone(){
        }
    }
?>