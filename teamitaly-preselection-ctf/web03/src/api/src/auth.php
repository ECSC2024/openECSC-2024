<?php

require_once 'db.php';

function get_logged_user(){
    $headers = getallheaders();
    $auth = $headers['Authorization'] ?? '';

    if (empty($auth)) {
        return null;
    }

    $db = get_db();

    $stmt = $db->prepare('SELECT username FROM users WHERE token = :token');
    $stmt->execute(['token' => $auth]);
    $user = $stmt->fetch();

    if ($user === false) {
        echo json_encode(['error' => 'Invalid token']);
        exit;
    }

    $username = $user['username'];
    
    return $username;
}