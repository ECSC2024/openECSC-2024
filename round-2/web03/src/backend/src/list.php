<?php

include 'classes/autoload.php';

if ( ! ( $user = UserSession::getSession() ) ) {
	header( 'Location: register.php' );
	die();
}

include_once ( 'header.php' );

$note_service = new NotesService( $user );

$notes = $note_service->list();

echo '<h3>Your notes</h3>';
echo '<ul class="list-group col-md-6 col-lg-4 my-3 mx-auto">';
 
foreach ( $notes->notes as $note ) {
	echo '<li class="list-group-item"><a href="/view.php?id=' . $note . '">' . $note_service->view( $note )->title . '</a></li>';
}

echo '</ul>';

?>


<?php
include_once ( 'footer.php' );
?>