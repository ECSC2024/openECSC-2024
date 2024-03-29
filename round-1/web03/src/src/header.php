<html>
  <head>
    <title>Life Quiz</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
  </head>
  <body>

  <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container-fluid">
            <a class="navbar-brand" href="/">Life Quiz</a>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    <?php 
                        if (isset($_SESSION['user'])) {
                            echo '<li class="nav-item">
                                <a class="nav-link" href="/quiz.php">Quiz</a>
                            </li>';
                            echo '<li class="nav-item">
                                <a class="nav-link" href="/prize.php">Prize</a>
                            </li>';
                            echo '<li class="nav-item">
                                <a class="nav-link" href="/reset.php">Reset points</a>
                            </li>';
                        } else {
                            echo '<li class="nav-item">
                                <a class="nav-link" href="/login.php">Login</a>
                            </li>';
                        }
                    ?>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container my-3 text-center">