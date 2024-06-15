<?php
session_start();

require_once __DIR__ . '/utils.php';

$user = getLoggedUser();

if(!$user){
    header('Location: /login.php');
    exit();
}

require_once __DIR__ . '/header.php';
?>

<div class="h-screen flex items-center justify-center pb-32 flex-col">

    <?php if($user['is_admin']){ ?>
        <p class="mb-3 text-lg block">
            Welcome admin, here you go: <?php 
                // includes $FLAG variable
                require_once __DIR__ . '/flag.php';
                echo $FLAG; 
            ?>
        </p>
    <?php } else {?>
        <p class="mb-3 text-lg block">
            Nice try, come back when you are admin :^)
        </p>
    <?php } ?>
</div>

<?php require_once __DIR__ . '/footer.php' ?>