<nav class="navbar navbar-expand-lg bg-body-tertiary fixed-top border-bottom py-0">
	<div class="container-fluid">
		<a class="navbar-brand d-flex gap-3 align-items-center" href="#" style="font-family: Pacifico; font-size: 1.5rem;">
			<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" style="width: 2.5rem; height: 2.5rem;">
				<path stroke-linecap="round" stroke-linejoin="round" d="M6.827 6.175A2.31 2.31 0 0 1 5.186 7.23c-.38.054-.757.112-1.134.175C2.999 7.58 2.25 8.507 2.25 9.574V18a2.25 2.25 0 0 0 2.25 2.25h15A2.25 2.25 0 0 0 21.75 18V9.574c0-1.067-.75-1.994-1.802-2.169a47.865 47.865 0 0 0-1.134-.175 2.31 2.31 0 0 1-1.64-1.055l-.822-1.316a2.192 2.192 0 0 0-1.736-1.039 48.774 48.774 0 0 0-5.232 0 2.192 2.192 0 0 0-1.736 1.039l-.821 1.316Z" />
				<path stroke-linecap="round" stroke-linejoin="round" d="M16.5 12.75a4.5 4.5 0 1 1-9 0 4.5 4.5 0 0 1 9 0ZM18.75 10.5h.008v.008h-.008V10.5Z" />
			</svg>

			Sharepic
		</a>
		<div class="collapse navbar-collapse" id="navbarSupportedContent">
			<form class="d-flex ms-auto" role="search">
				<input class="form-control me-2" type="search" placeholder="Search (coming soon)" aria-label="Search">
			</form>
			<div class="ms-auto d-flex align-items-center gap-3">
				<?php
				if (isset($_SESSION['username'])) {
				?>
					<?= htmlentities($_SESSION['username'], ENT_NOQUOTES) ?>
					<div style="aspect-ratio: 1; width: 2.5rem;" class="bg-body-secondary p-1 rounded-circle">
						<img src="/user.webp" class="rounded-circle" style="height: 100%;" alt="" srcset="">
					</div>
				<?php
				} else {
				?>
					<a href="/login.php"><button type="button" class="btn btn-primary btn-sm">Log in</button></a>
				<?php } ?>
			</div>
		</div>
</nav>