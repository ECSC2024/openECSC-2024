<?php

session_start();

if (!isset($_SESSION['user'])) {
    header('Location: index.php');
    exit();
}

include_once 'db.php';
include_once 'header.php';

$conn = db_connect();
$user = $_SESSION['user'];

$sql = "SELECT * FROM users WHERE id = '$user'";
$result = $conn->query($sql);
if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $question_id = $row['question_id'];
    $points = $row['points'];
    $username = $row['username'];
} else {
    echo "Please refresh the page";
    session_destroy();
    $conn->close();
    exit();
}


if ($points < $PRIZE_POINTS) {
    echo "<p>You have $points points</p><p>You need to answer $PRIZE_POINTS questions correctly to get the prize :/</p>";
} else {
    
    if ($question_id != -1) {
        
        // Print the prize
        $cmd = "convert -draw " . escapeshellarg("text 0,1219 \"$username\"") . " -pointsize 100 -gravity Center /trophy.jpg /prizes/$user.jpg &";
        echo system($cmd, $retval);

        if ($retval !== 0) {
            echo "Error getting your prize";
            $conn->close();
            exit();
        }

        $sql = "UPDATE users SET question_id = -1 WHERE id = '$user'";
        $conn->query($sql);
    }

    echo "Your prize is ready, you can find it <a href='/prize.php'>here</a>!<br>";
}

$conn->close();
