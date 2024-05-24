<?php


class UserSession extends Service {

	private function __construct() {
		$url = getenv( "AUTH_SERVICE" );
		parent::__construct( $url );

		$this->jwt_key = $this->getRequest( '/key' );
	}

	public static function getSession() {
		if ( ! isset( $_COOKIE['session'] ) || ! isset( $_COOKIE['username'] ) ) {
			return FALSE;
		}

		$username = $_COOKIE['username'];
		$token = $_COOKIE['session'];

		$auth_service = AuthService::get();

		if ( ! $auth_service->is_logged( $username, $token ) ) {
			return FALSE;
		}

		return new User( $username, $token );
	}

	public static function setSession( $user ) {
		setcookie( 'session', $user->getToken(), httponly: TRUE );
		setcookie( 'username', $user->getUsername(), httponly: TRUE );
	}

	public static function destroySession() {
		unset( $_COOKIE['session'] );
		unset( $_COOKIE['username'] );

		setcookie( 'session', '', -1 );
		setcookie( 'username', '', -1 );
	}

	public static function csrfInit() {
		if ( ! ( $csrf = self::csrfGet() ) || $csrf == '' ) {
			$token = bin2hex( random_bytes( 16 ) );
			setcookie( 'csrf', $token, httponly: TRUE );
			$_COOKIE['csrf'] = $token;
		}

	}

	public static function csrfCheck( $csrf ) {
		if ( ! ( $csrf_cookie = self::csrfGet() ) ) {
			return FALSE;
		}
		return $csrf_cookie === $csrf;
	}

	public static function csrfGet() {
		if ( ! isset( $_COOKIE['csrf'] ) || $_COOKIE['csrf'] == '' ) {
			return FALSE;
		}
		return htmlentities( $_COOKIE['csrf'] );
	}



}