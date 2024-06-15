<?php
session_start();

require_once __DIR__ . '/utils.php';

$user = getLoggedUser();
$error = "";

if ($user != null) {
    header('Location: /');
    exit;
}

function do_login()
{
    global $error;

    if (
        !isset($_POST['username']) ||
        !isset($_POST['password'])
    ) {
        $error = "Missing data";
        return;
    }

    $username = $_POST['username'];
    $password = $_POST['password'];

    if (
        !is_string($username) ||
        !is_string($password)
    ) {
        $error = "Invalid data";
        return;
    }

    require_once __DIR__ . '/DB.php';
    $db = DB::getInstance();

    $user = $db->exec('SELECT * FROM users WHERE username = :username', [
        'username' => $username
    ]);

    if (count($user) == 0) {
        $error = "Invalid credentials";
        return;
    }

    $user = $user[0];

    if (!$user['verified']) {
        $error = "Account not verified, please check your email";
        return;
    }

    if (!password_verify($password, $user['password'])) {
        $error = "Invalid credentials";
        return;
    }

    // create a new session
    session_reset();

    $_SESSION['user_id'] = $user['id'];

    header('Location: /');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    do_login();
}

require_once __DIR__ . '/header.php';
?>

<div class="h-screen flex items-center justify-center pb-32">

    <div class="p-8 border-2 border-gray-200 border-dashed rounded-lg w-full md:w-2/5 mx-4">
        <h2 class="text-3xl font-extrabold mb-6">Login</h2>

        <?php if ($error !== "") { ?>
            <div class="flex items-start mb-6 text-sm font-bold text-red-500">
                <?php echo $error ?>
            </div>
        <?php } ?>

        <form action="/login.php" method="post">
            <div class="mb-6">
                <label for="username" class="block mb-2 text-sm font-medium text-gray-900">Username</label>
                <input type="username" id="username" name="username" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5" placeholder="matteo.rossi" required>
            </div>
            <div class="mb-6">
                <label for="password" class="block mb-2 text-sm font-medium text-gray-900">Password</label>
                <input type="password" id="password" name="password" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5" placeholder="•••••••••" required>
            </div>

            <button type="submit" class="text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm w-full md:w-auto px-5 py-2.5 text-center">Login</button>

            <div class="flex items-start mt-6">
                <span class="text-sm font-semibold text-gray-900"> <a href="/passwordless_login.php" class="text-blue-600 hover:underline">Password-less login</a></label>
            </div>

            <div class="flex items-start mt-6">
                <span class="text-sm font-semibold text-gray-900">If you still don't have an account <a href="/register.php" class="text-blue-600 hover:underline">register for free!</a></label>
            </div>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/footer.php' ?>