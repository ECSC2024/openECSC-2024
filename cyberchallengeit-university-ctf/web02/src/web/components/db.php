<?php

try {
	$db = new PDO("sqlite:/app/web/db.sqlite");
	$db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_OBJ);

	$db->exec('CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, name TEXT, email TEXT, message TEXT, language TEXT)');
} catch (PDOException $e) {
	print_r($e);
	die("Could not connect to the database");
}
