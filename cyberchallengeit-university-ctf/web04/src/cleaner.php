<?php

// Not part of the challenge, is a helper script to clean up the user-data folder
// This script will run in the background and delete files older than 2 hours

$whitelist = [
	"/app/web/user-data/e20f5c02-a867-4745-b739-34b7b4f14e1c.jpg",
	"/app/web/user-data/6ae3970f-da20-4005-8080-b7dbb3a10695.jpg",
	"/app/web/user-data/05bbebad-1a73-4216-a0cc-3abf8bc0f075.jpg",
	"/app/web/user-data/3294863e-8f66-4a90-a327-812d869cea99.jpg",
	"/app/web/user-data/d3aa5acc-1613-4193-bb2e-e93d9d15d59a.jpg",
	"/app/web/user-data/5bbf5b39-7516-4260-899b-ad4a4689fcac.jpg",
];

while (true) {
	// list all files in the folder
	$files = glob('/app/web/user-data/*');
	$threshold = strtotime('-2 hours');

	// delete files older than 2 hours
	foreach ($files as $file) {
		// skip files in whitelist
		if (in_array($file, $whitelist)) {
			continue;
		}

		if (is_file($file) && filemtime($file) < $threshold) {
			unlink($file);
		}
	}

	sleep(60);
}
