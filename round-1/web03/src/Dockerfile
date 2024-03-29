FROM php:8.1-apache

RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli

RUN apt update && apt install -y imagemagick

RUN mkdir /prizes
RUN chown -R www-data:www-data /prizes

COPY trophy.jpg /trophy.jpg

RUN convert -draw 'text 0,1219 "openECSC{U_4re_4_Qu1z_m4s7er}"' -pointsize 60 -gravity Center /trophy.jpg /prizes/flag.jpg