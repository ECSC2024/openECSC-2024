FROM alpine:3.18.3

RUN apk update && apk add php81 php81-fpm php81-curl php81-session php81-common php81-zip php81-pdo php81-pdo_sqlite nginx supervisor

RUN addgroup -S web && adduser -H -S --shell /sbin/nologin -g web web

COPY web /app/web

COPY supervisord/supervisord.conf /supervisord.conf
COPY nginx/nginx.conf /etc/nginx/nginx.conf
RUN echo "clear_env = no" >> /etc/php81/php-fpm.d/www.conf

# I guess there are better ways to fix this, but who cares
RUN chown -R web:web /var/log/

RUN chmod -R 755 /app
RUN chown -R web:web /app/web

CMD ["supervisord", "-c", "/supervisord.conf"]