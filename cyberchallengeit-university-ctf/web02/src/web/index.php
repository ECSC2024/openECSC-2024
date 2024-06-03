<?php

session_start();

require_once './components/db.php';
require_once './components/i18n.php';
require_once './components/Hashcash.php';
require_once './components/secret.php';

if (isset($_POST['name']) && isset($_POST['email']) && isset($_POST['message']) && isset($_POST['pow'])) {
	try {
		if ($_POST['pow'] !== getenv('CHECKER_TOKEN')) {
			if(!isset($_SESSION['pow'])) {
				throw new InvalidArgumentException();
			}
			$hashcash = new \TheFox\Pow\Hashcash(26, $_SESSION['pow']);
			$hashcash->verify($_POST['pow']);
		}

		$name = $_POST['name'];
		$email = $_POST['email'];
		$message = $_POST['message'];

		$query = $db->prepare('INSERT INTO messages (name, email, message, language) VALUES (:name, :email, :message, :language)');
		$query->execute(['name' => htmlentities($name), 'email' => htmlentities($email), 'message' => htmlentities($message), 'language' => $_SERVER['HTTP_ACCEPT_LANGUAGE']]);

		// send headless to the details page
		$actions = [
			'actions' => [
				[
					'type' => 'request',
					'url' => getenv('CHALLENGE_URL')
				],
				[
					'type' => 'set-cookie',
					'name' => 'admin',
					'value' => getenv('ADMIN_TOKEN'),
					'path' => '/',
					'httpOnly' => true,
					'sameSite' => 'Strict'
				],
				[
					'type' => 'set-cookie',
					'name' => 'flag',
					'value' => get_flag(),
					'httpOnly' => false
				],
				[
					'type' => 'request',
					'url' => getenv('CHALLENGE_URL') . '/admin.php?id=' . $db->lastInsertId()
				],
				[
					'type' => 'sleep',
					'time' => 3
				]
			]
		];

		$context = stream_context_create([
			'http' => [
				'method' => 'POST',
				'header' => [
					'Content-Type: application/json',
					'X-Auth: ' .  getenv('HEADLESS_AUTH'),
				],
				'content' => json_encode($actions),
				'ignore_erros' => TRUE
			]
		]);
		$response = file_get_contents('http://'.getenv('HEADLESS_HOST'), false, $context);

		$_SESSION['flash'] = 'Message successfully sent! An admin will get back to you soon.';
	} catch (InvalidArgumentException $e) {
		$_SESSION['error'] = 'Invalid proof of work';
	} catch (Exception $e) {
		$_SESSION['error'] = 'There was an error sending the message to the admins :(';
	}
}

$_SESSION['pow'] = bin2hex(random_bytes(6));

?>

<?php require_once './components/header.php' ?>
<?php require_once './components/navbar.php' ?>

<div class="container" style="padding: 4rem 0 4rem 0;">
	<?php
	if (isset($_SESSION['flash'])) {
	?>
		<div class="alert alert-success mx-auto" style="max-width: 44rem" role="alert">
			<?= $_SESSION['flash'] ?>
		</div>
	<?php
		unset($_SESSION['flash']);
	}

	if (isset($_SESSION['error'])) {
	?>
		<div class="alert alert-danger mx-auto" style="max-width: 44rem" role="alert">
			<?= $_SESSION['error'] ?>
		</div>
	<?php
		unset($_SESSION['error']);
	}
	?>

	<h1 style="font-size: 5rem; margin-bottom: 1rem;">
		<?= t('home.welcome') ?>
	</h1>
	<h3>
		<?= t('home.intro') ?>
	</h3>

	<main style="margin-top: 5rem; max-width: 44rem; margin-left: auto;">
		<h5><?= t('home.description') ?></h5>
		<figure data-rehype-pretty-code-figure="">
			<pre style=" background-color:#282c34;color:#abb2bf" tabindex="0" data-language="html" data-theme="one-dark-pro"><code data-language="html" data-theme="one-dark-pro" style="display:grid"><span data-line=""><span style="color:#ABB2BF">&lt;</span><span style="color:#E06C75">div</span><span style="color:#D19A66"> class</span><span style="color:#ABB2BF">=</span><span style="color:#98C379">"container-fluid"</span><span style="color:#ABB2BF">&gt;</span></span>
				<span data-line="" data-highlighted-line=""><span style="color:#ABB2BF"> &lt;</span><span style="color:#E06C75">h1</span><span style="color:#ABB2BF">&gt;</span><span style="color:#be5046">&lt;?=</span><span style="color:#61afef"> t</span><span>(</span><span style="color:#98c379">'home.title'</span>) <span style="color:#be5046">?&gt;</span><span>&lt;/</span><span style="color:#E06C75">h1</span><span style="color:#ABB2BF">&gt;</span></span>
				<span data-line="" data-highlighted-line=""><span style="color:#ABB2BF"> &lt;</span><span style="color:#E06C75">h3</span><span style="color:#ABB2BF">&gt;</span><span style="color:#be5046">&lt;?=</span><span style="color:#61afef"> t</span><span>(</span><span style="color:#98c379">'home.intro'</span>) <span style="color:#be5046">?&gt;</span><span>&lt;/</span><span style="color:#E06C75">h3</span><span style="color:#ABB2BF">&gt;</span></span>
				<span data-line=""><span style="color:#ABB2BF"> </span></span>
				<span data-line=""><span style="color:#ABB2BF"> &lt;</span><span style="color:#E06C75">section</span><span style="color:#ABB2BF">&gt;</span></span></code></pre>
		</figure>
	</main>

	<section style="margin-bottom: 15rem;">
		<h2 style="text-align: center; font-size: 3rem; margin-top: 5rem;"><?= t('form.title') ?></h2>

		<div class="card mt-4 mx-auto" style="max-width: 44rem">
			<div class="card-body">
				<form method="POST">
					<div class="mb-3">
						<label for="name" class="form-label"><?= t('form.name') ?></label>
						<input type="text" class="form-control" id="name" name="name">
					</div>
					<div class="mb-3">
						<label for="email" class="form-label"><?= t('form.email') ?></label>
						<input type="email" class="form-control" id="email" name="email" aria-describedby="emailHelp">
						<div id="emailHelp" class="form-text"><?= t('form.emailDisclaimer') ?></div>
					</div>
					<div class="mb-3">
						<label for="message" class="form-label"><?= t('form.message') ?></label>
						<textarea class="form-control" id="message" name="message" rows="3"></textarea>
					</div>
					<div class="mb-3">
						<label for="pow" class="form-label">Proof of Work of <?= $_SESSION['pow'] ?></label>
						<input type="pow" class="form-control" id="pow" name="pow" aria-describedby="emailHelp">
						<div id="emailHelp" class="form-text">Solve with <kbd>hashcash -mCb26 "<?= $_SESSION['pow'] ?>"</kbd> or <a href="https://pow.cybersecnatlab.it/?data=<?= $_SESSION['pow'] ?>&bits=26">using the online tool</a></div>
					</div>
					<div class="text-center mt-4">
						<button type="submit" class="btn btn-warning">&nbsp;&nbsp;&nbsp;&nbsp;<?= t('form.send') ?>&nbsp;&nbsp;&nbsp;&nbsp;</button>
					</div>
				</form>
			</div>
		</div>
	</section>
</div>

<?php require_once './components/footer.php' ?>