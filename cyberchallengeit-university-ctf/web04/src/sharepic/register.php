<?php

session_start();

require_once './components/db.php';

if (isset($_POST['username'])) {
	// generate random password
	$password = bin2hex(random_bytes(10));

	// create account
	try {
		$stmt = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
		$stmt->execute([
			"username" => $_POST['username'],
			"password" => password_hash($password, PASSWORD_DEFAULT),
		]);

		// set session
		$_SESSION['username'] = $_POST['username'];
		$_SESSION['flash'] = "Your password is: $password";

		header('Location: /');
		die('Redirecting to /');
	} catch (PDOException $e) {
		$error = "Username already taken";
	}
}

?>

<?php require_once './components/header.php' ?>

<div class="container" style="padding: 5.5rem 0 4rem 0;">
	<div class="card mb-4 mx-auto" style="max-width: 28rem">
		<div class="card-body pb-5">
			<h1 class="text-center mb-5 mt-2" style="font-family: Pacifico;">Sharepic</h1>

			<form method="POST" class="px-5">
				<div class="mb-3">
					<input type="text" class="form-control" id="username" name="username" placeholder="Username">
				</div>
				<?php
				if (isset($error)) {
				?>
					<div class="alert alert-danger" role="alert">
						<?= $error ?>
					</div>
				<?php
				}
				?>
				<button type="submit" class="btn btn-primary w-100">Sign up</button>
			</form>
		</div>
	</div>

	<div class="card mb-4 mx-auto" style="max-width: 28rem">
		<div class="card-body py-4 text-center">
			Have an account? <a href="/login.php" class="link-primary">Log in</a>
		</div>
	</div>
</div>

<?php require_once './components/footer.php' ?>