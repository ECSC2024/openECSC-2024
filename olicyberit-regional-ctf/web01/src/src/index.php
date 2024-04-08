<!doctype html>
<html lang="en">

<head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Bootstrap CSS -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-EVSTQN3/azprG1Anm3QDgpJLIm9Nao0Yz1ztcQTwFspd3yD65VohhpuuCOmLASjC" crossorigin="anonymous">

    <title>Pretty please</title>
</head>

<body>

    <?php 
    if (isset($_GET['source'])){
        highlight_file('index.php');
        exit();
    }
    ?>

    <div class="container text-center">
        <div class="row justify-content-center my-3">
            <div class="col-10 all">

                <?php
                if (isset($_POST['how'])) {

                    switch ($_POST['how']) {
                        case 'now':
                            echo '<div class="alert alert-danger">Please, learn some good manners</div>';
                            break;
                        case 'please':
                            echo '<div class="alert alert-danger">Mmmmh, you can do better</div>';
                            break;
                        case 'gabibbo':
                            echo '<div class="alert alert-danger">How do you know my name?!</div>';
                            echo '<style>body{ background: url("gabibbo.jpg") fixed center; background-size: cover } form, h3 {background-color: white}</style>';
                            break;
                        case 'pretty please':
                            include_once('secret.php');
                            echo '<div class="alert alert-success">Now we are talking! ' . $FLAG . '</div>';
                            break;
                        default:
                            echo '<div class="alert alert-danger">I don\'t understand you...</div>';
                            break;
                    }
                }
                ?>

                <h3 class="my-4">Do you want my flag? You just need to ask for it nicely :)</h3>

                <form method="post">
                    <div class="mb-3">
                        <span>
                        Can I have the flag,
                        <select name="how">
                            <option value="now">now</option>
                            <option value="please">please</option>
                            <option value="gabibbo">gabibbo</option>
                        </select>
                        ?
                        </span>
                    </div>
                    <div class="mb-3">
                        <input class="btn btn-primary" type="submit" value="Ask!">
                    </div>
                </form>

            </div>
        </div>
    </div>


    <div class="bottom_link" ><a href="/?source">Show source</a></div>

    <style>
    .bottom_link {
  position: fixed;
  left: 50%;
  bottom: 20px;
  transform: translate(-50%, -50%);
  margin: 0 auto;
}
</style>

</body>

</html>