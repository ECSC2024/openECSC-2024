<?php

class NoteException extends Exception {

}

class NotesService extends Service {

	private $header_auth;

	public function __construct( $user ) {
		$url = getenv( "NOTES_SERVICE" );
		parent::__construct( $url );

		$token = $user->getToken();
		$this->header_auth = "Authentication: $token";
	}

	public function list() {
		$output = $this->getRequest( "/list", [ $this->header_auth ] );

		return $output;
	}

	public function new( $title, $body ) {
		$body = htmlentities( $body );
		$title = htmlentities( $title );
		$data = [ 
			'title' => $title,
			'body' => $body
		];

		return $this->postRequest( '/new', $data, [ $this->header_auth ] );

	}

	public function edit( $note_id, $title, $body ) {
		$body = htmlentities( $body );
		$title = htmlentities( $title );
		$data = [ 
			'title' => $title,
			'body' => $body
		];

		return $this->postRequest( "/edit/$note_id", $data, [ $this->header_auth ] );

	}

	public function view( $note_id ) {
		$note = $this->getRequest( "/view/$note_id", [ $this->header_auth ] );
		if ( $note == '' ) {
			return FALSE;
		}

		return $note->note;

	}



}

