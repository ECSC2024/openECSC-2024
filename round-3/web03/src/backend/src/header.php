<!doctype html>
<html lang="en">

<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title>Notes</title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet"
		integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
	<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
	<script>
		MathJax = {
			tex: {
				displayMath: [['[math]', '[/math]']]
			},
			svg: {
				fontCache: 'global'
			},
			loader: { load: ['ui/safe'] },
			options: {
				safeOptions: {
					allow: {
						URLs: 'safe',
						classes: 'safe',
						cssIDs: 'safe',
						styles: 'safe'
					}
				}
			}
		}
	</script>
	<script src="https://polyfill.io/v3/polyfill.min.js?features=es6"></script>
	<script id="MathJax-script" async src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-mml-chtml.js"></script>


</head>

<body>

	<nav class="navbar navbar-expand-lg navbar-light bg-light">
		<div class="container-fluid">
			<a class="navbar-brand" href="/">Notes</a>
			<button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
				aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
				<span class="navbar-toggler-icon"></span>
			</button>
			<div class="collapse navbar-collapse" id="navbarNav">
				<ul class="navbar-nav">
					<?php if ( UserSession::getSession() ) { ?>
						<li class="nav-item">
							<a class="nav-link" href="/list.php">Your notes</a>
						</li>
						<li class="nav-item">
							<a class="nav-link" href="/new.php">New note</a>
						</li>
						<li class="nav-item">
							<a class="nav-link" href="/support.php">Support</a>
						</li>
						<li class="nav-item">
							<a class="nav-link" href="/logout.php">Logout</a>
						</li>
					<?php } else { ?>
						<li class="nav-item">
							<a class="nav-link" href="/register.php">Register</a>
						</li>
						<li class="nav-item">
							<a class="nav-link" href="/login.php">Login</a>
						</li>
					<?php } ?>



				</ul>
			</div>
		</div>
	</nav>

	<div class="container my-5 text-center">

		<?php
		if ( isset( $error_msg ) ) {
			echo '<div class="alert alert-danger" role="alert">' . htmlentities( $error_msg ) . '</div>';
		}
		if ( isset( $success_msg ) ) {
			echo '<div class="alert alert-success" role="alert">' . htmlentities( $success_msg ) . '</div>';
		}
		?>