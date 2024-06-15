<?php

session_start();

require_once __DIR__ . '/utils.php';
require_once __DIR__ . '/DB.php';

$user = getLoggedUser();

function do_login()
{
    $token = $_GET['token'];

    if (
        !is_string($token)
    ) {
        return;
    }

    $db = DB::getInstance();

    $tokens = $db->exec('SELECT * FROM login_token WHERE token = :token', [
        'token' => hash('sha256', $token),
    ]);

    if(count($tokens) == 0) {
        return;
    }

    $user_id = $tokens[0]['user_id'];

    $user = $db->exec('SELECT * FROM users WHERE id = :user_id', [
        'user_id' => $user_id
    ]);

    if (count($user) == 0) {
        return;
    }
    $user = $user[0];

    $db->exec('DELETE FROM login_token WHERE id = :token_id', [
        'token_id' => $tokens[0]['id']
    ]);

    $_SESSION['user_id'] = $user['id'];

    header('Location: /');
    die();
}

if (isset($_GET['token'])) {
    do_login();
}

header('Location: /login.php');
?>