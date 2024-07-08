FROM alpine:3.20

RUN apk update && apk add apache2 php82-apache2 
RUN apk add php82 php82-pdo_sqlite

# use API without .php extension and set the default file to hello.php
RUN sed -i 's#Options Indexes FollowSymLinks#Options Indexes FollowSymLinks MultiViews\nAddType application/x-httpd-php .php\nDirectoryIndex hello.php#' /etc/apache2/httpd.conf

WORKDIR /app
COPY . /app

RUN rm -r /var/www/localhost/htdocs
RUN ln -s /app/src /var/www/localhost/htdocs

RUN chmod +x /app/startup.sh

CMD ["/app/startup.sh"]