<?php
include 'classes/autoload.php';

if ( ! ( $user = UserSession::getSession() ) ) {
	header( 'Location: register.php' );
	die();
}

$note_service = new NotesService( $user );

if ( isset( $_POST['title'] ) && isset( $_POST['body'] ) && isset( $_POST['csrf'] ) ) {

	if ( ! UserSession::csrfCheck( $_POST['csrf'] ) ) {
		echo 'CSRF token mismatch';
		die();
	}

	$note = $note_service->new( $_POST['title'], $_POST['body'] );
	header( "Location: view.php?id=$note->id" );
	die();
}
UserSession::csrfInit();
include_once ( 'header.php' );

?>



<form method="post" class="form-group mx-auto col-md-6 col-lg-4 my-3">

	<label for="title" class="form-label">Title</label>
	<input class="form-control mb-2" id="title" name="title">

	<label for="body" class="form-label">Body</label>
	<input class="form-control mb-2" id="body" name="body">

	<input type="hidden" name="csrf" value="<?php echo UserSession::csrfGet(); ?>">

	<button type="submit" id="submit" class="btn btn-primary my-3 w-100">Create</button>
</form>



<?php
include_once ( 'footer.php' );
?>