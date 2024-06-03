<nav class="navbar navbar-expand-lg border-bottom border-body" style="background-color: #105448;" data-bs-theme="dark">
	<div class="container">
		<a class="navbar-brand" href="#"><?= t('seo.title') ?></a>
		<button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
			<span class="navbar-toggler-icon"></span>
		</button>
		<div class="collapse navbar-collapse" id="navbarSupportedContent">
			<ul class="navbar-nav ms-auto">
				<li class="nav-item dropdown">
					<a class="nav-link dropdown-toggle active" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
						<?= get_flag_icon(get_language()) ?>
						<?= t('languageName') ?>
					</a>
					<ul class="dropdown-menu">
						<?php
						foreach (available_languages() as $lang) {
						?>
							<li><a class="dropdown-item" href="#" data-lang="<?= $lang ?>">
									<?= get_flag_icon($lang) ?>
									<?= t('languages.' . $lang) ?>
								</a>
							</li>
						<?php
						}
						?>
					</ul>
					<script>
						document.querySelectorAll('[data-lang]').forEach(item => {
							item.addEventListener('click', e => {
								document.cookie = `lang=${e.target.dataset.lang};path=/`;
								location.reload();
							});
						});
					</script>
				</li>
			</ul>
		</div>
	</div>
</nav>