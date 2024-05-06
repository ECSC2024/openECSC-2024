<?php
include 'classes/autoload.php';

include_once ( 'header.php' );
?>

<h3>Welcome to our new, original, innovative note platform</h3>

<?php
if ( $user = UserSession::getSession() ) {
	echo '<p class="my-3">You are logged in as ' . htmlentities($user->getUsername()) . '</p>';
	echo '<p class="my-3"><a href="/list.php">View your notes</a></p>';
} else {
	echo '<p class="my-3">You are not logged in</p>';
	echo '<p class="my-3"><a href="/login.php">Login</a> or <a href="/register.php">register</a> </p>';
}

include_once ( 'footer.php' );
?>