FROM alpine:3.20

RUN apk update && apk add apache2 php82-apache2 
RUN apk add curl

WORKDIR /app
COPY . /app

RUN rm -r /var/www/localhost/htdocs
RUN ln -s /app/server /var/www/localhost/htdocs

RUN chmod +x /app/run.sh
CMD ["/app/run.sh"]