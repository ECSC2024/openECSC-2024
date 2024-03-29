<?php

function db_connect() {
    // sqlite db
    $db = new SQLite3('/data/fileshare.db');
    return $db;
}

function db_init() {
    $db = db_connect();
    $db->exec('CREATE TABLE IF NOT EXISTS files (id TEXT PRIMARY KEY, filename TEXT, content_type TEXT, size INTEGER)');
    $db->close();
}