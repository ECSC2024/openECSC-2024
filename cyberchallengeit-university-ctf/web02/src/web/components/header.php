<?php require_once './components/i18n.php' ?>

<!DOCTYPE html>
<html lang="en">

<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title><?= t('seo.title'); ?></title>
	<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH" crossorigin="anonymous">
	<link rel="preconnect" href="https://fonts.googleapis.com">
	<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
	<link href="https://fonts.googleapis.com/css2?family=Pacifico&display=swap" rel="stylesheet">

	<link rel="icon" type="image/svg" href="/favicon.svg">

	<style>
		a.dropdown-item,
		a.nav-link:has(svg) {
			display: flex;
			align-items: center;
			gap: .5rem;
			padding-top: .4rem;
			padding-bottom: .4rem;
		}

		a.dropdown-item svg,
		a.nav-link:has(svg) svg {
			width: 2rem;
			border-radius: 3px;
		}

		@import url("https://fonts.googleapis.com/css2?family=Cousine&family=Patua+One&display=swap");

		figure[data-rehype-pretty-code-figure] {
			margin: 0;
		}

		code {
			padding: 2px 3px;
			background: #1a1a1a;
			border: solid 1px #2a2a2a;
			border-radius: 4px;
			font-size: 0.9rem;
		}

		pre {
			padding: 1rem 0;
			margin-top: 2rem;
			margin-bottom: 2.25rem;
			border-radius: 8px;
			font-size: 0.9rem;
			overflow-x: auto;
		}

		pre>code {
			all: unset;
		}

		figure[data-rehype-pretty-code-figure] code {
			counter-reset: line;
			box-decoration-break: clone;
		}

		figure[data-rehype-pretty-code-figure] [data-line] {
			padding: 0 1rem;
		}

		figure[data-rehype-pretty-code-figure] [data-line-numbers]>[data-line]::before {
			counter-increment: line;
			content: counter(line);
			display: inline-block;
			width: 1rem;
			margin-right: 1rem;
			text-align: right;
			color: #666;
		}

		figure[data-rehype-pretty-code-figure] [data-highlighted-line] {
			background-color: #ffffdd19;
		}

		figure[data-rehype-pretty-code-figure] [data-highlighted-chars] {
			border-radius: 0.375rem;
			padding: 0.25rem;
			background-color: #ffffdd20;
		}

		[data-rehype-pretty-code-title] {
			background-color: #282c34;
			display: inline-block;
			position: relative;
			margin-left: -1rem;
			margin-top: 1rem;
			padding: 0.5rem 1.5rem 0.5rem 1.5rem;
			border-bottom: solid 2px #32936f;
			font-size: 0.9rem;
			font-family: monospace;
			border-top-left-radius: 8px;
			border-top-right-radius: 8px;
		}

		[data-rehype-pretty-code-title]+pre {
			margin-top: 0;
			border-top-left-radius: 0;
		}

		pre {
			margin-bottom: 1.75rem;
		}
	</style>
</head>

<body data-bs-theme="dark">