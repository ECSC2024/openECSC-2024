<?php

require_once 'auth.php';

$username = get_logged_user();

if ($username === null) {
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $db = get_db();

    $stmt = $db->prepare('SELECT id, name, description FROM recipes WHERE username = :username');
    $stmt->execute(['username' => $username]);

    $res = $stmt->fetchAll();
    $recipes = [];
    foreach ($res as &$recipe) {
        $recipes[] = [
            'id' => $recipe['id'],
            'name' => $recipe['name'],
            'description' => $recipe['description']
        ];
    }

    echo json_encode($recipes);
} else if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $body = json_decode(file_get_contents('php://input'), true);

    if ($body === null) {
        echo json_encode(['error' => 'Invalid JSON body']);
        exit;
    }

    if (!isset($body['name']) || !isset($body['description'])) {
        echo json_encode(['error' => 'Missing name or description']);
        exit;
    }

    $name = $body['name'];
    $description = $body['description'];

    $db = get_db();

    try {
        $stmt = $db->prepare('INSERT INTO recipes (username, name, description) VALUES (:username, :name, :description)');
        $stmt->execute(['username' => $username, 'name' => $name, 'description' => $description]);
        $id = $db->lastInsertId();
    } catch (PDOException $e) {
        echo json_encode(['error' => $e->getMessage()]);
        exit;
    }

    echo json_encode(['message' => 'Recipe created', 'id' => $id]);
} else if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    $db = get_db();

    $body = json_decode(file_get_contents('php://input'), true);

    if ($body === null) {
        echo json_encode(['error' => 'Invalid JSON body']);
        exit;
    }

    if (!isset($body['id'])) {
        echo json_encode(['error' => 'Missing id']);
        exit;
    }

    $id = $body['id'];

    $stmt = $db->prepare('DELETE FROM recipes WHERE id = :id AND username = :username');
    $stmt->execute(['id' => $id, 'username' => $username]);

    if ($stmt->rowCount() === 0) {
        echo json_encode(['error' => 'Recipe not found']);
        exit;
    }

    echo json_encode(['message' => 'Recipe deleted']);
} else if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
    $body = json_decode(file_get_contents('php://input'), true);

    if ($body === null) {
        echo json_encode(['error' => 'Invalid JSON body']);
        exit;
    }

    if (!isset($body['id']) || !isset($body['name']) || !isset($body['description'])) {
        echo json_encode(['error' => 'Missing id, name, or description']);
        exit;
    }

    $id = $body['id'];
    $name = $body['name'];
    $description = $body['description'];

    $db = get_db();

    $stmt = $db->prepare('UPDATE recipes SET name = :name, description = :description WHERE id = :id AND username = :username');
    $stmt->execute(['name' => $name, 'description' => $description, 'id' => $id, 'username' => $username]);

    if ($stmt->rowCount() === 0) {
        echo json_encode(['error' => 'Recipe not found']);
        exit;
    }

    echo json_encode(['message' => 'Recipe updated']);
} else {
    echo json_encode(['error' => 'Invalid request method']);
    exit;
}