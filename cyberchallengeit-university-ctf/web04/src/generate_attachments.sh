#!/bin/bash

rm -rf ../attachments/*

cp -r nginx ../attachments/nginx
cp -r supervisord ../attachments/supervisord
cp -r sharepic ../attachments/sharepic
cp -r docker-compose.yml ../attachments/docker-compose.yml
cp -r Dockerfile ../attachments/Dockerfile
cp -r init.sql ../attachments/init.sql
cp -r cleaner.php ../attachments/cleaner.php

cd ../attachments

sed -i "s/CCIT{.*}/CCIT{REDACTED}/" init.sql
sed -i "s/MYSQL_ROOT_PASSWORD: .*$/MYSQL_ROOT_PASSWORD: redacted/" docker-compose.yml
sed -i "s/DB_PASS: .*$/DB_PASS: redacted/" docker-compose.yml
sed -i "s/MYSQL_PASSWORD: .*$/MYSQL_PASSWORD: redacted/" docker-compose.yml

zip -r sharepic.zip nginx supervisord sharepic docker-compose.yml Dockerfile init.sql cleaner.php
rm -rf nginx supervisord sharepic docker-compose.yml Dockerfile init.sql cleaner.php