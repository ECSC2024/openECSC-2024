<?php

include 'classes/autoload.php';

if ( ! ( $user = UserSession::getSession() ) ) {
	header( 'Location: register.php' );
	die();
}

session_start();

if ( isset( $_POST['url'] ) && isset( $_POST['url'] ) && isset( $_POST['csrf']) && isset($_POST['pow']) && isset( $_SESSION['pow_seed']) && $_SESSION['pow_seed'] != '')   {

	if ( ! UserSession::csrfCheck( $_POST['csrf'] ) ) {
		echo 'CSRF token mismatch';
		die();
	}
    
    $pow = $_POST['pow'];
    if(is_array($pow) || $pow === '' || ($pow !== $_ENV['CHECKER_POW'] && !str_ends_with(md5($pow . $_SESSION['pow_seed']), '000000'))) {
        die('Wrong PoW!');
    };
	$url = $_POST['url'];	

	if ( preg_match( '#^[a-fA-F0-9]{20}$#', $url ) === 1 ) {

        $chall_url = getenv('CHALL_URL');
		$username = md5( openssl_random_pseudo_bytes( 8 ) );

		$actions = array();
		$actions[] = array( 'type' => 'request', 'url' => $chall_url . '/register.php' );
		$actions[] = array( 'type' => 'set-cookie', 'name' => 'flag', 'value' => getenv('FLAG'));
		$actions[] = array( 'type' => 'type', 'element' => '#username', 'value' => $username );
		$actions[] = array( 'type' => 'click', 'element' => '#submit' );

		
		$actions[] = array( 'type' => 'request', 'url' => $chall_url . '/view.php?id=' . $url);
        $actions[] = array('type' => 'sleep', 'time' => 5);
        
        $data = array('actions' => $actions, 'browser' => 'chrome');
        $data = json_encode($data);

		$options = array(
			'http' => array(
				'header' => [ "Content-type: application/json", "X-Auth: " . getenv( 'HEADLESS_AUTH' ) ],
				'method' => 'POST',
				'content' => $data
			)
		);

        $context = stream_context_create($options);
        $result = file_get_contents('http://' . getenv('HEADLESS_HOST'), false, $context);

		if ( $result === FALSE ) {
			$error_msg = 'Sorry, there was an error sending your message';
		} else {
			$success_msg = 'Thank you, our agent ' . $username . ' is taking care of your problem';
		}
	} else {
		$error_msg = 'Sorry, the note id is not valid';
	}

}

UserSession::csrfInit();
$_SESSION['pow_seed'] = bin2hex(openssl_random_pseudo_bytes(8));
include_once ( 'header.php' );
?>



<form method="post" class="form-group mx-auto col-md-6 col-lg-4 my-3">
	<label for="url" class="form-label">Note Id</label>
	<input class="form-control mb-2" id="url" name="url">
    <label for="pow" class = "form-label"> str_ends_with(md5($pow . "<?php echo $_SESSION['pow_seed'];?>"), '000000')</label>
    <input class="form-control mb-2" id="pow" name="pow" placeholder="$pow">
	<input type="hidden" name="csrf" value="<?php echo UserSession::csrfGet(); ?>">

	<button type="submit" class="btn btn-primary my-3 w-100">Ask for support</button>
</form>



<?php
include_once ( 'footer.php' );
?>