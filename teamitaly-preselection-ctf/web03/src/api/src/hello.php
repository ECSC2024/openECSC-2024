<?php

require_once 'auth.php';

$username = get_logged_user();

if ($username === null) {
    $username = 'guest';
}

echo json_encode(['message' => "Hello $username!"]);
?>