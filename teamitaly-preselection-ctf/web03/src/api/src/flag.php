<?php

$body = json_decode(file_get_contents('php://input'), true);


if ($body === null) {
    echo json_encode(['error' => 'Invalid JSON body']);
    exit;
}

if (!isset($body['guess'])) {
    echo json_encode(['error' => 'Missing guess']);
    exit;
}

$guess = $body['guess'];
$random = bin2hex(random_bytes(10));

if ($guess === $random) {
    echo json_encode(['message' => getenv('FLAG')]);
} else {
    echo json_encode(['error' => 'Wrong guess', 'answer' => $random]);
}
