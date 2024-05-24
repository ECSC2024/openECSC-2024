<?php

class UserException extends Exception {
}

class User {
	private $username;
	private $token;

	public function __construct( $username, $token ) {
		$this->username = $username;
		$this->token = $token;
	}

	public static function register( $username, $password ) {
		$auth_service = AuthService::get();

		$res = $auth_service->register( $username, $password );

		if ( ! $res->status )
			throw new UserException( $res->err );

		return new User( $username, $res->token );
	}

	public static function login( $username, $password ) {
		$auth_service = AuthService::get();

		$res = $auth_service->login( $username, $password );

		if ( ! $res->status )
			throw new UserException( $res->err );

		return new User( $username, $res->token );
	}

	public function getToken() {
		return $this->token;
	}

	public function getUsername() {
		return $this->username;
	}
}