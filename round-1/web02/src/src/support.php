<?php
session_start();

include_once('header.php');

if (isset($_POST['email']) || isset($_POST['fileid']) || isset($_POST['message'])) {
    
    $fileid = $_POST['fileid'];
    if (preg_match('/^[a-f0-9]{30}$/', $fileid) === 1) {

        $url = 'http://' . getenv('HEADLESS_HOST');
        $chall_url = 'http://' . getenv('WEB_DOM');
        $act1 = array('type' => 'request', 'url' => $chall_url);
        $act2 = array('type' => 'set-cookie', 'name' => 'flag', 'value' => getenv('FLAG'));
        $act3 = array('type' => 'request', 'url' => $chall_url . '/download.php?id=' . $fileid);
        
        $data = array('actions' => [$act1, $act2, $act3], 'browser' => 'chrome');
        $data = json_encode($data);

        $options = array(
            'http' => array(
                'header'  => "Content-type: application/json\r\n" . "X-Auth: " . getenv('HEADLESS_AUTH') . "\r\n",
                'method'  => 'POST',
                'content' => $data
            )
        );

        $context  = stream_context_create($options);
        $result = file_get_contents($url, false, $context);

        if ($result === FALSE) {
            echo '<div class="alert alert-danger" role="alert">Sorry, there was an error sending your message.</div>';
        } else {
            echo '<div class="alert alert-success" role="alert">Thank you, we are taking care of your problem!</div>';
        }
        
    } else {
        echo '<div class="alert alert-success" role="alert">Thank you for your submission</div>';
    }
}

?>
<h1>Support page</h1>
<br>
<h5>Our service is in beta testing, please contact us if you find any bug!</h5>
<br>

<form method="post" class="form-group mx-auto col-md-6 my-3">
    <label for="email" class="form-label">Email</label>
    <input class="form-control mb-2" id="email" name="email">

    <laber for="fileid" class="form-label">File ID</label>
    <input class="form-control mb-2" id="fileid" name="fileid">

    <label for="message" class="form-label">Message</label>
    <textarea class="form-control mb-2" id="message" name="message" rows="3"></textarea>

    <button type="submit" class="btn btn-primary my-3 w-100">Send</button>
</form>




<?php
include_once('footer.php');
?>