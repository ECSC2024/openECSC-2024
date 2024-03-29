<?php

session_start();

if (!isset($_SESSION['user'])) {
    header('Location: index.php');
    exit();
}

include_once 'header.php';

$user = $_SESSION['user'];

if (file_exists("/prizes/$user.jpg")) {
    echo "Congratulations, you won!<br>Here's you throphy<br>";
    echo '<img class="w-100" src="/throphy.php">';
} else {
    echo "No prize for you, play our game to win!<br>";
    echo '<a class="btn btn-primary mt-3" href="/quiz.php">Play the game</a>';
}