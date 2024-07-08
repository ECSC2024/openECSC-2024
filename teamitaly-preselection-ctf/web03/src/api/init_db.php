<?php

try {
    $db = new PDO('sqlite:/app/db.sqlite');
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $db->exec("CREATE TABLE IF NOT EXISTS users (
                        username VARCHAR(30) PRIMARY KEY NOT NULL, 
                        token VARCHAR(40) NOT NULL)");
                        
    $db->exec("CREATE TABLE IF NOT EXISTS recipes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name VARCHAR(100) NOT NULL,
                        description TEXT NOT NULL,
                        username VARCHAR(30) NOT NULL,
                        FOREIGN KEY (username) REFERENCES users(username))");

    $db = null;

    chmod('/app/db.sqlite', 0777);
    chmod('/app', 0777);
    
    echo "Database initialized successfully.\n";
} catch (PDOException $e) {
    echo "Database initialization failed: " . $e->getMessage() . "\n";
    exit(1);
}

?>