<?php
include 'classes/autoload.php';

if ( isset( $_POST['username'] ) && isset( $_POST['password'] ) && isset( $_POST['csrf'] ) ) {

	if ( ! UserSession::csrfCheck( $_POST['csrf'] ) ) {
		echo 'CSRF token mismatch';
		die();
	}

	try {
		$user = User::login( $_POST['username'], $_POST['password'] );
		UserSession::setSession( $user );
		header( 'Location: /' );
	} catch (UserException $e) {
		$error_msg = $e->getMessage();
	}

}

UserSession::csrfInit();
include_once ( 'header.php' );

?>

<form method="post" class="form-group mx-auto col-md-6 col-lg-4 my-3">
	<label for="username" class="form-label">Username</label>
	<input class="form-control mb-2" id="username" name="username">

	<label for="password" class="form-label">Password</label>
	<input class="form-control mb-2" id="password" name="password" type="password">

	<input type="hidden" name="csrf" value="<?php echo UserSession::csrfGet(); ?>">
	<button type="submit" id="submit" class="btn btn-primary my-3 w-100">Login</button>
</form>


<?php
include_once ( 'footer.php' );
?>