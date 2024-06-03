FROM alpine:3.18.3

RUN apk update && apk add nodejs npm mariadb mariadb-client tzdata bash coreutils supervisor

ENV TZ=Europe/Rome
RUN cp /usr/share/zoneinfo/Europe/Rome /etc/localtime

RUN addgroup -S web && adduser -H -S --shell /sbin/nologin -g web web

COPY src/package.json /app/web/package.json
COPY src/package-lock.json /app/web/package-lock.json

WORKDIR /app/web

RUN npm ci

COPY src /app/web

COPY supervisord/supervisord.conf /supervisord.conf
COPY docker-mariadb-entrypoint.sh /usr/local/bin/docker-mariadb-entrypoint.sh

COPY flag.txt /flag_uwu.txt
RUN chmod 444 /flag_uwu.txt
RUN chown root:root /flag_uwu.txt

# I guess there are better ways to fix this, but who cares
RUN chown -R web:web /var/log/
RUN mkdir /run/mysqld
RUN chown -R mysql:mysql /run/mysqld


RUN chmod -R 755 /app
RUN chown -R web:web /app/web

CMD ["supervisord", "-c", "/supervisord.conf"]