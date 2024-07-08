<?php 

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['error' => 'Invalid request method']);
    exit;
}

$body = json_decode(file_get_contents('php://input'), true);

if ($body === null) {
    echo json_encode(['error' => 'Invalid JSON body']);
    exit;
}

if (!isset($body['username'])) {
    echo json_encode(['error' => 'Missing username']);
    exit;
}

$username = $body['username'];
$token = bin2hex(random_bytes(20));

include_once 'db.php';

$db = get_db();

try {
    $stmt = $db->prepare('INSERT INTO users (username, token) VALUES (:username, :token)');
    $stmt->execute(['username' => $username, 'token' => $token]);
} catch (PDOException $e) {
    if ($e->errorInfo[1] === 19) {
        echo json_encode(['error' => "User $username already exists"]);
        exit;
    }
    echo json_encode(['error' => $e->getMessage()]);
    exit;
}

echo json_encode(['message' => "User $username registered", 'token' => 'Authorization: '.$token]);