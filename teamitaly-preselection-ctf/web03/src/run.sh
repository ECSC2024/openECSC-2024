#!/usr/bin/env sh

RUN sed -i "s#Options Indexes FollowSymLinks#Options Indexes FollowSymLinks\nSetEnv API_HOST $API_HOST#" /etc/apache2/httpd.conf

httpd -D FOREGROUND