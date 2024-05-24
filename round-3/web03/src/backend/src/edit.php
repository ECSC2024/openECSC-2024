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

if ( $_SERVER['REQUEST_METHOD'] === 'POST' ) {
	if ( ! UserSession::csrfCheck( $_POST['csrf'] ) ) {
		die( 'CSRF check failed' );
	}

	$note_service->edit( $_GET['id'], $_POST['title'], $_POST['body'] );
	header( 'Location: /view.php?id=' . $_GET['id'] );
	die();
}

include_once ( 'header.php' );
$note = $note_service->view( $_GET['id'] );
if ( ! $note ) {
	die( 'Note not found' );
}
?>

<h3> <?= $note->title; ?> </h3>

<form method="post" class="form-group mx-auto col-md-6 my-3">
	<input class="form-control mb-2" type="text" name="title" placeholder="Title">
	<textarea class="form-control mb-2" id="body" name="body"><?= $note->body; ?></textarea>

	<input type="hidden" name="csrf" value="<?php echo UserSession::csrfGet(); ?>">
	<button type="submit" class="btn btn-primary my-3 w-100">Save</button>
</form>



<?php
include_once ( 'footer.php' );
?>