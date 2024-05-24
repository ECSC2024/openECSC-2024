<?php

require_once ( 'vendor/autoload.php' );

function autoloader( $class ) {
	$path = 'classes/' . $class . '.class.php';

	if ( file_exists( $path ) )
		include $path;
}

spl_autoload_register( 'autoloader' );

use voku\helper\HtmlMin;

function minify( $buffer )
{
	$htmlMin = new HtmlMin();
	return $htmlMin->minify( $buffer );
}

ob_start( 'minify' );