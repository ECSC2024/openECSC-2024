<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AuthException extends Exception {

}

class AuthService extends Service {
	private static $inst = FALSE;

	private $jwt_key;

	private function __construct() {
		$url = getenv( "AUTH_SERVICE" );
		parent::__construct( $url );

		$this->jwt_key = file_get_contents( $url . '/key' );
	}

	public static function get() {
		if ( ! self::$inst )
			self::$inst = new AuthService();

		return self::$inst;
	}

	public function login( $username, $password ) {
		$data = [ 
			'username' => $username,
			'password' => $password
		];

		return $this->postRequest( '/login', $data );

	}

	public function register( $username, $password ) {
		$data = [ 
			'username' => $username,
			'password' => $password
		];

		return $this->postRequest( '/register', $data );
	}

	public function is_logged( $username, $token ) {
		try {
			$data = JWT::decode( $token, new Key( $this->jwt_key, 'RS256' ) );
		} catch (UnexpectedValueException $e) {
			return FALSE;
		}

		if ( $data->username !== $username ) {
			return FALSE;
		}
		;

		return $data;
	}


}