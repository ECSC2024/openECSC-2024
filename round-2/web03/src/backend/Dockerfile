FROM php:8.1-apache
RUN apt update && apt upgrade -y && apt-get install -y git 
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer

COPY src/ /var/www/html
COPY composer.json /var/www/html
COPY composer.lock /var/www/html
WORKDIR /var/www/html

RUN composer update