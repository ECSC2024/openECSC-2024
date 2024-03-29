FROM php:8.1-apache

RUN mkdir /uploads
RUN chown -R www-data:www-data /uploads

RUN mkdir /data
COPY fileshare.db /data/fileshare.db
RUN chown -R www-data:www-data /data

COPY /src /var/www/html
