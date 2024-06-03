#!/bin/bash

rm -rf ../attachments/*

cp -r supervisord ../attachments/supervisord
cp -r src ../attachments/src
cp -r docker-compose.yml ../attachments/docker-compose.yml
cp -r docker-mariadb-entrypoint.sh ../attachments/docker-mariadb-entrypoint.sh
cp -r Dockerfile ../attachments/Dockerfile
cp -r init.sql ../attachments/init.sql

cd ../attachments

echo -n "CCIT{REDACTED_uUuUu}" > flag.txt

rm -rf src/node_modules

zip -r cyberton.zip supervisord src docker-compose.yml docker-mariadb-entrypoint.sh Dockerfile init.sql flag.txt
rm -rf supervisord src docker-compose.yml docker-mariadb-entrypoint.sh Dockerfile init.sql flag.txt