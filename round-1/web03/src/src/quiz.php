<?php

session_start();

include_once 'db.php';
include_once 'header.php';

$conn = db_connect();

$question_id = 1;

// If the user is not logged in, redirect
if (!isset($_SESSION['user'])) {
    echo "<meta http-equiv='refresh' content='0;url=login.php'>";
    $conn->close();
    exit();
} else {
    $user = $_SESSION['user'];
    
    // Get the current question
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
    
    if (!isset($_POST['answer'])) {
        echo "<div class='alert alert-primary'>You have $points points</div>";
    }
    
    // If the user has answered all the questions, show the flag
    if ($points >= $PRIZE_POINTS) {
        echo "Congratulations! You did a great job, get your prize <a href='/get_prize.php'>here</a>!<br>";
        $conn->close();
        exit();
    }
}


if ($question_id > $QUESTION_N) {
    echo "You answered all the questions, but you need at least $PRIZE_POINTS points to get the prize :(<br>";
    echo "<a class='btn btn-primary mt-3' href='/reset.php'>Reset your progress</a>";
    $conn->close();
    exit();
}

$db_question_id = (($question_id - 1) % 5) + 1;


$sql = "SELECT * FROM questions WHERE id = $db_question_id";
$result = $conn->query($sql);
if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $question = $row['question'];
    $answers = json_decode($row['answers'], true);
} else {
    echo "No question found";
    $conn->close();
    exit();
}

// If the user has submitted an answer, check if it is correct
if (isset($_POST['answer'])) {
    $answer = $_POST['answer'];
    $correct_answer = $answers[array_rand($answers)];
    
    echo "<h3 class='mb-3'>Question $question_id</h3>";
    $question_id++;
    if ($answer === $correct_answer) {
        echo "<p>Correct!</p>";
        
        $sql = "UPDATE users SET points = points+1 WHERE id = '$user'";
        $conn->query($sql);
    } else {
        echo "<p>Incorrect!<br>The correct answer was: $correct_answer</p>";
    }
    
    if ($question_id > $QUESTION_N) {
        echo "<p>You answered all the questions!</p>";
        echo "<a class='btn btn-primary my-3' href='quiz.php'>Next</a><br>";
    } else {
        echo "<a class='btn btn-primary my-3' href='quiz.php'>Next question</a><br>";
    }
    
    $sql = "UPDATE users SET question_id = $question_id WHERE id = '$user'";
    $conn->query($sql);
    $conn->close();
    exit();
}

$conn->close();

echo "<h3>Question $question_id</h3>";
echo "<p class='my-3'>$question</p>";
echo "<form method='post' class='col-4 mx-auto'>";
echo '<div class="list-group">';
foreach ($answers as $option) {
    echo '<input class="btn-check me-1" type="radio" name="answer" id="'. $option .'" value="' . $option . '">';
    echo '<label class="btn btn-light my-1" for="' . $option . '">';
    echo $option;
    echo '</label>';
}
echo '</div>';
echo "<input class='btn btn-primary w-100 mt-3' type='submit' value='Submit'>";
echo "</form>";

?>



