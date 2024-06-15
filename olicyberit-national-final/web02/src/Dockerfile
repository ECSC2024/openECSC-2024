FROM php:8.2-fpm

RUN apt update
# install pdo for mysql
RUN docker-php-ext-install mysqli pdo pdo_mysql

COPY ./src /var/www/html

USER www-data