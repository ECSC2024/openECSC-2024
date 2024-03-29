<?php

session_start();

if (!isset($_SESSION['user'])) {
    header('Location: index.php');
    exit();
}

$user = $_SESSION['user'];

if (file_exists("/prizes/$user.jpg")) {
    readfile("/prizes/$user.jpg");
} else {
    echo "No prize for you";
}