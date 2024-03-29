<?php
session_start();
include_once 'header.php';
?>

<div class="container my-5">
    <h1 class="text-center">Welcome to Life Quiz</h1>
    <p class="text-center mb-4">Answer the questions to get a prize, easy peasy</p>

    <?php
    if (isset($_SESSION['user'])) {
        echo '<a href="quiz.php" class="btn btn-primary">Start Quiz</a>';
    } else {
        echo '<a href="login.php" class="btn btn-primary">Login to start</a>';
    }
    ?>
