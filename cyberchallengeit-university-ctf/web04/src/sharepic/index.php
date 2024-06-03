<?php

session_start();

require_once './components/db.php';
require_once './components/utils.php';


function image_upload($file)
{
	// Controls maximum file size
	if ($file['size'] > 1024 * 1024) {
		throw new Exception("Image is too large");
	}

	// This actually loads and parses the image, no way to upload something else
	$verifyimg = getimagesize($file['tmp_name']);

	// Checks if legit image file
	if ($verifyimg['mime'] !== "image/jpeg" && $verifyimg['mime'] !== "image/jpg") {
		throw new Exception("Only JPEG image files are allowed!");
	}

	$imgname = uuidv4();

	if (move_uploaded_file($file['tmp_name'], __DIR__ . '/user-data/' . $imgname . '.jpg')) {
		// This is only to protect from dossing other players
		chmod(__DIR__ . '/user-data/' . $imgname . '.jpg', 0444);

		return $imgname;
	} else {
		throw new Exception("Unexpected server configuration issue, please ping an admin");
	}
}


if (isset($_FILES['picture']) && isset($_POST['description'])) {
	if (!isset($_SESSION['username'])) {
		$_SESSION['error'] = "You need to be logged in to create a post";
		header("Location: /login.php");
		exit();
	}

	$picture = $_FILES['picture'];
	$description = $_POST['description'];

	try {
		$filename = image_upload($picture);

		$stmt = $db->prepare("INSERT INTO posts (user_id, picture, description) VALUES ((SELECT id FROM users WHERE username = :username), :picture, :description)");
		$stmt->execute([
			"username" => $_SESSION['username'],
			"picture" => $filename,
			"description" => $description,
		]);

		$_SESSION['flash'] = "Post created successfully";
	} catch (Exception $e) {
		$_SESSION['error'] = $e->getMessage();
	}
}

if (isset($_SESSION['username'])) {
	// If logged in retrieve public and personal posts
	$stmt = $db->prepare("SELECT * FROM posts INNER JOIN users ON posts.user_id = users.id WHERE users.username = :username OR users.is_public = TRUE ORDER BY posts.created_at DESC");
	$stmt->execute(["username" => $_SESSION['username']]);
} else {
	// else, retrieve only public posts
	$stmt = $db->prepare("SELECT * FROM posts INNER JOIN users ON posts.user_id = users.id WHERE users.is_public = TRUE ORDER BY posts.created_at DESC");
	$stmt->execute();
}
$posts = $stmt->fetchAll();

?>

<?php require_once './components/header.php' ?>
<?php require_once './components/navbar.php' ?>

<div class="container" style="padding: 5.5rem 0 4rem 0;">
	<?php
	if (isset($_SESSION['flash'])) {
	?>
		<div class="alert alert-success mx-auto" style="max-width: 36rem" role="alert">
			<?= $_SESSION['flash'] ?>
		</div>
	<?php
		unset($_SESSION['flash']);
	}

	if (isset($_SESSION['error'])) {
	?>
		<div class="alert alert-danger mx-auto" style="max-width: 36rem" role="alert">
			<?= $_SESSION['error'] ?>
		</div>
	<?php
		unset($_SESSION['error']);
	}
	?>

	<?php
	foreach ($posts as $post) {
	?>
		<div class="card mb-4 mx-auto" style="max-width: 36rem">
			<div class="card-body pb-0 pt-2">
				<p class="card-title"><strong><u>@<?= htmlentities($post->username, ENT_NOQUOTES) ?></u></strong></p>
			</div>
			<img src="/user-data/<?= $post->picture ?>.jpg">
			<div class="card-body">
				<p class="card-text"><?= preg_replace('/#([^\s]+)/', '<u class="text-primary-emphasis">#$1</u>', htmlentities($post->description, ENT_NOQUOTES)) ?></p>
				<p class="card-text"><small class="text-body-secondary">Shared <?= friendly_time($post->created_at) ?></small></p>
			</div>
			<div class="card-footer bg-white">
				<?php
				$random_comments = generate_random_comments();
				foreach ($random_comments as $comment) {
				?>
					<div class="d-flex gap-2 small mb-1">
						<div><strong><u>@<?= $comment["handle"] ?></u></strong></div>
						<div><?= $comment["comment"] ?></div>
					</div>
				<?php } ?>
			</div>
		</div>
	<?php } ?>
</div>

<div class="container-fluid bg-body-tertiary position-fixed bottom-0 border-top">
	<footer class="d-flex justify-content-around align-items-center my-2">
		<?php
		if (!isset($_SESSION['username'])) {
		?>
			<a href="/login.php">
			<?php
		}
			?>
			<button class="bg-transparent border-0" <?= isset($_SESSION['username']) ? 'data-bs-toggle="modal" data-bs-target="#uploadModal"' : '' ?>>
				<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" style="width: 2.25rem">
					<path stroke-linecap="round" stroke-linejoin="round" d="M12 9v6m3-3H9m12 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
				</svg>
			</button>
			<?php
			if (!isset($_SESSION['username'])) {
			?>
			</a>
		<?php
			}
		?>
	</footer>
</div>

<!-- Upload modal -->
<div class="modal fade" id="uploadModal" tabindex="-1" aria-labelledby="uploadModalLabel" aria-hidden="true">
	<div class="modal-dialog modal-dialog-centered modal-dialog-scrollable">
		<div class="modal-content">
			<div class="modal-header">
				<h1 class="modal-title fs-5" id="exampleModalLabel">Create new post</h1>
				<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
			</div>
			<form method="post" enctype="multipart/form-data">
				<div class="modal-body">
					<div class="mb-3">
						<input class="form-control" name="picture" type="file" id="formFile" accept="image/jpeg" required>
					</div>
					<div class="mb-3">
						<textarea placeholder="Post description" name="description" class="form-control" id="exampleFormControlTextarea1" rows="3" required></textarea>
					</div>

				</div>
				<div class="modal-footer">
					<button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
					<button type="submit" class="btn btn-primary">Save changes</button>
				</div>
			</form>
		</div>
	</div>
</div>


<?php require_once './components/footer.php' ?>