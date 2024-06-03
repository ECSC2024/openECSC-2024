<?php

try {
	$DB_HOST = getenv("DB_HOST");
	$DB_NAME = getenv("DB_NAME");
	$DB_USER = getenv("DB_USER");
	$DB_PASS = getenv("DB_PASS");

	$db = new PDO("mysql:host=$DB_HOST;dbname=$DB_NAME", $DB_USER, $DB_PASS, [
		PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_OBJ,
	]);
} catch (PDOException $e) {
	print_r($e);
	die("Could not connect to the database");
}
