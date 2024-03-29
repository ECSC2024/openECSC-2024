<?php

session_start();

if (!isset($_SESSION['user'])) {
    header('Location: /');
    exit();
}

include_once 'db.php';
include_once 'header.php';

$user = $_SESSION['user'];
    
$conn = db_connect();

$sql = "UPDATE users SET points = 0, question_id = 1 WHERE id = '$user'";
$conn->query($sql);
$conn->close();

echo "Your progress has been reset!<br>";
echo "<a class='btn btn-primary mt-3' href='/quiz.php'>Start the quiz</a>";

?>



