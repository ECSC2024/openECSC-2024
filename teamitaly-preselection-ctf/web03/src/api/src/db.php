<?php

function get_db() {
    try {
        $db = new PDO('sqlite:/app/db.sqlite');
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $db;
    } catch (PDOException $e) {
        echo "Something is wrong, please contact an administrator";
        exit(1);
    }
}
