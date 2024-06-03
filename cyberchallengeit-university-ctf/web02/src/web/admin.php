<?php

require_once './components/db.php';
require_once './components/i18n.php';

// only the headless can access this page
if (!isset($_COOKIE['admin']) || $_COOKIE['admin'] !== getenv('ADMIN_TOKEN')) {
	http_response_code(403);
	die('nope');
}

if (!isset($_GET['id'])) {
	http_response_code(404);
	die('nope');
}

$id = $_GET['id'];

$query = $db->prepare('SELECT * FROM messages WHERE id = :id');
$query->execute(['id' => $id]);
$message = $query->fetch();

if (!$message) {
	http_response_code(404);
	die('nope');
}

?>

<?php require_once './components/header.php' ?>
<?php require_once './components/navbar.php' ?>

<div class="container" style="padding: 4rem 0 4rem 0;">
	<div class="card">
		<div class="card-body">
			<h3>Message details</h3>
			<table class="table table-stripped mt-3">
				<tbody>
					<tr>
						<th scope="row">Name</th>
						<td><?= $message->name; ?></td>
					</tr>
					<tr>
						<th scope="row">Email</th>
						<td><?= $message->email; ?></td>
					</tr>
					<tr>
						<th scope="row">Message</th>
						<td><?= $message->message; ?></td>
					</tr>
					<tr>
						<th scope="row">Language</th>
						<td><?= $message->language; ?></td>
					</tr>
				</tbody>
			</table>
		</div>
	</div>
</div>
</div>

<?php require_once './components/footer.php' ?>