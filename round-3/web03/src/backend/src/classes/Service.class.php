<?php

class ServiceException extends Exception {

}

abstract class Service {
	private $url;

	protected function __construct( $url ) {
		$this->url = $url;
	}

	protected function getRequest( $path, $headers = [] ) {
		$fullurl = $this->url . $path;

		$context = stream_context_create( [ 
			'http' => [ 
				'method' => 'GET',
				'header' => $headers,
				'ignore_erros' => TRUE
			]
		] );
		return $this->doRequest( $fullurl, $context );
	}

	protected function postRequest( $path, $body = '', $headers = [] ) {
		$fullurl = $this->url . $path;
		$json_body = json_encode( $body );

		array_push( $headers, 'Content-Type: application/json' );


		$context = stream_context_create( [ 
			'http' => [ 
				'method' => 'POST',
				'header' => $headers,
				'content' => $json_body,
				'ignore_erros' => TRUE
			]
		] );
		return $this->doRequest( $fullurl, $context );
	}

	private function doRequest( $url, $context ) {
		$response = file_get_contents( $url, FALSE, $context );
		try {
			$output = json_decode( $response, flags: JSON_THROW_ON_ERROR );
		} catch (JsonException $e) {
			throw new ServiceException( "Cannot decode JSON. Service response: " . $response );
		}

		return $output;
	}



}