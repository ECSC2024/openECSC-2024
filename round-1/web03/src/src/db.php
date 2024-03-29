<?php

$QUESTION_N = 15;
$PRIZE_POINTS = 15;


function db_connect() {
    // Connect to the database
    $username = 'root';
    $password = 'password';
    $host = $_ENV['DB_HOST'];
    
    $conn = new mysqli($host, $username, $password, "db");

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    return $conn;
}