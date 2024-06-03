FROM alpine:3.18.3

RUN apk update && apk add php81 php81-fpm php81-curl php81-session php81-common php81-zip php81-pdo php81-pdo_mysql nginx supervisor

RUN addgroup -S web && adduser -H -S --shell /sbin/nologin -g web web

COPY sharepic /app/sharepic

COPY supervisord/supervisord.conf /supervisord.conf
COPY nginx/nginx.conf /etc/nginx/nginx.conf
RUN echo "security.limit_extensions = FALSE" >> /etc/php81/php-fpm.d/www.conf
RUN echo "clear_env = no" >> /etc/php81/php-fpm.d/www.conf

# I guess there are better ways to fix this, but who cares
RUN chown -R web:web /var/log/

RUN chmod -R 755 /app
RUN chown -R web:web /app/sharepic/user-data
RUN chmod 444 /app/sharepic/user-data/*

# add the file cleaner
COPY cleaner.php /app/cleaner.php

CMD ["supervisord", "-c", "/supervisord.conf"]