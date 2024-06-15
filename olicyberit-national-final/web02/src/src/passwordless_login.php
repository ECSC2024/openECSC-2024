<?php
session_start();

require_once __DIR__ . '/utils.php';

$error = "";
$user = getLoggedUser();

if ($user != null) {
    header('Location: /');
    exit();
}

function passwordless_login()
{
    global $error;

    if (
        !isset($_POST['email'])
    ) {
        $error = "Missing data";
        return;
    }

    $email = $_POST['email'];

    if (
        !is_string($email) ||
        !filter_var($email, FILTER_VALIDATE_EMAIL)
    ) {
        $error = "Invalid data";
        return;
    }

    require_once __DIR__ . '/DB.php';
    $db = DB::getInstance();

    $user = $db->exec('SELECT * FROM users WHERE email = :email', [
        'email' => $email
    ]);

    if (count($user) === 0) {
        // avoid enumeration
        return;
    }

    $user = $user[0];

    $token = bin2hex(random_bytes(32));

    $domain_name = $_SERVER['HTTP_HOST'];
    send_mail(
        $email,
        "Login",
        "Go to http://$domain_name/token_login.php?token=$token to perform the login!"
    );

    $db->exec('INSERT INTO login_token (user_id, token) VALUES (:user_id, :token)', [
        'user_id' => $user['id'],
        'token' => hash('sha256', $token),
    ]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    passwordless_login();
}

require_once __DIR__ . '/header.php';
?>

<div class="h-screen flex items-center justify-center pb-32">

    <div class="p-8 border-2 border-gray-200 border-dashed rounded-lg w-full md:w-2/5 mx-4">
        <h2 class="text-3xl font-extrabold mb-6">Password-less login</h2>

        <?php if ($error !== "") { ?>
            <div class="flex items-start mb-6 text-sm font-bold text-red-500">
                <?php echo $error ?>
            </div>
        <?php } ?>

        <form action="/passwordless_login.php" method="post">
            <div class="mb-6">
                <label for="email" class="block mb-2 text-sm font-medium text-gray-900">Email address</label>
                <input type="email" id="email" name="email" , class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5" placeholder="matteo.rossi@example.com" required>
            </div>
            <button type="submit" class="text-white bg-blue-700 hover:bg-blue-800 focus:ring-4 focus:outline-none focus:ring-blue-300 font-medium rounded-lg text-sm w-full md:w-auto px-5 py-2.5 text-center">Login</button>
        </form>
    </div>
</div>

<?php require_once __DIR__ . '/footer.php' ?>