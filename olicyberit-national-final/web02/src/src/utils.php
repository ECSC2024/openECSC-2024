<?php

define('OK', 200);
define('BAD_REQUEST', 400);
define('UNAUTHORIZED', 401);
define('METHOD_NOT_ALLOWED', 405);
define('NOT_FOUND', 404);
define('INTERNAL_SERVER_ERROR', 500);

function exitIfRequested($callingFile){
    if (strcasecmp(str_replace('\\', '/', $callingFile), $_SERVER['SCRIPT_FILENAME']) == 0) {
        http_response_code(NOT_FOUND);
        exit();
    }
}
exitIfRequested(__FILE__);

function checkEmail($email){
    return is_string($email) && filter_var($email, FILTER_VALIDATE_EMAIL) && str_ends_with($email, '@fakemail.olicyber.it');
}

function getLoggedUser(){
    if (!isset($_SESSION['user_id'])){
        return null;
    }

    require_once __DIR__ . '/DB.php';

    $db = DB::getInstance();
    $users = $db->exec('SELECT * FROM users WHERE id = :id', [
        'id' => $_SESSION['user_id']
    ]);

    if(count($users) === 0){
        return null;
    }

    return $users[0];
}

function checkPassword($password){
    if(strlen($password) < 8){
        return false;
    }
    return true;
}

function send_mail($email, $subject, $body){
    $data = array(
        'from' => 'no-reply@fakemail.olicyber.it',
        'to' => $email,
        'subject' => $subject,
        'body' => $body,
        'token' => $_ENV['MAIL_TOKEN']
    );

    $jsonData = json_encode($data);

    $url = 'http://' . $_ENV['MAIL_HOST'] . '/api/add_email';

    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
    curl_setopt($curl, CURLOPT_POST, 1);
    curl_setopt($curl, CURLOPT_POSTFIELDS, $jsonData);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, TRUE);

    curl_exec($curl);
    $status_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);

    curl_close($curl);

    if($status_code !== 201){
        return false;
    }

    return true;
}
?>