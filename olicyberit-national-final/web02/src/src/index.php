<?php
session_start();

require_once __DIR__ . '/utils.php';

$user = getLoggedUser();

require_once __DIR__ . '/header.php';
?>

<div class="h-screen flex items-center justify-center pb-32 flex-col">

    <p class="mb-3 text-lg block">
        This website does literally nothing.
    </p>

    <p class="mb-3 text-lg block">
        Let's see 5 things you could do instead of looking at this website:
        <ul>
            <li>Touch some grass</li>
            <li>Listen to <a class="underline text-blue-600" href="https://open.spotify.com/album/64ZUYtdEVuy4OXk63R579s?si=317qAvP4SJeiuqBYOGR9HA">OBE</a> (album of years 2021-2022-2023)</li>
            <li>Look at Dario Moccia's <a class="underline text-blue-600" href="https://www.youtube.com/watch?v=ZCSm7CRIi88">compilation</a></li>
            <li>Cook 1kg of <a class="underline text-blue-600" href="https://www.tavolartegusto.it/ricetta/schiacciata-toscana-ricetta-originale/">schiacciata</a></li>
            <li>Pray the Gabibbo <a class="underline text-blue-600" href="/gabibbo_gymbro.jpg">gymbro</a></li>
        </ul>
    </p>
</div>

<?php require_once __DIR__ . '/footer.php' ?>