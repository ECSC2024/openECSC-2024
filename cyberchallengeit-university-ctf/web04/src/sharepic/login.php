<?php
session_start();

require_once './components/db.php';

if (isset($_POST['username']) && isset($_POST['password'])) {
	$stmt = $db->prepare("SELECT * FROM users WHERE username = :username");
	$stmt->execute([
		"username" => $_POST['username'],
	]);
	$user = $stmt->fetch();

	if ($user && password_verify($_POST['password'], $user->password)) {
		$_SESSION['username'] = $user->username;
		header('Location: /');
		die('Redirecting to /');
	} else {
		$error = "Invalid username or password";
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
					<input type="text" class="form-control" id="username" name="username" placeholder="Username" required>
				</div>
				<div class="mb-3">
					<input type="password" class="form-control" id="password" name="password" placeholder="Password" required>
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
				<button type="submit" class="btn btn-primary w-100">Log in</button>
			</form>
		</div>
	</div>

	<div class="card mb-4 mx-auto" style="max-width: 28rem">
		<div class="card-body py-4 text-center">
			Don't have an account? <a href="/register.php" class="link-primary">Sign up</a>
		</div>
	</div>
</div>

<?php require_once './components/footer.php' ?>