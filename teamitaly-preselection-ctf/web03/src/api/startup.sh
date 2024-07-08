#!/bin/sh

# Initialize the SQLite database
php82 /app/init_db.php

# Start Apache in the foreground
httpd -D FOREGROUND