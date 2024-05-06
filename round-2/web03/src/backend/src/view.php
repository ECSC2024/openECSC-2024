<?php

include 'classes/autoload.php';

if ( ! ( $user = UserSession::getSession() ) ) {
	header( 'Location: register.php' );
	die();
}

$note_service = new NotesService( $user );

if ( ! isset( $_GET['id'] ) ) {
	header( 'Location: index.php' );
	die();
}

include_once ( 'header.php' );

$note = $note_service->view( $_GET['id'] );

if ( ! $note ) {
	die( 'Note not found' );
}

?>

<h3> <?= $note->title; ?> </h3>
<p><?= $note->body; ?></p>

<a class="btn btn-primary" href="/edit.php?id=<?= htmlentities($_GET['id']) ?>">Edit</a>
<?php
include_once ( 'footer.php' );
?>