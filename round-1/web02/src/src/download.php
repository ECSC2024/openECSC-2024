<?php

if (!isset($_GET['id'])) {
    header('Location: /');
    return;
}

$id = $_GET['id'];

if (preg_match('/^[a-f0-9]{30}$/', $id) !== 1) {
    header('Location: /');
    return;
}

include_once('db.php');

$db = db_connect();
$stmt = $db->prepare('SELECT * FROM files WHERE id = ?');
$stmt->bindParam(1, $id);
$result = $stmt->execute();
$row = $result->fetchArray(SQLITE3_ASSOC);

if ($row) {
    $path = "/uploads/$id";
    header('Content-Type: '. $row['content_type']);
    readfile($path);
} else {
    header('Location: /');
}
$db->close();

?>
