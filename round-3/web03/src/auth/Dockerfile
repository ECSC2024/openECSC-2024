FROM ubuntu:22.04

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y wget curl netcat dumb-init

RUN DEBIAN_FRONTEND="noninteractive" apt-get install -y python3 python3-pip nginx supervisor  \
 && pip3 install --no-cache-dir uWSGI==2.0.24 \
 && useradd -ms /bin/null web 


COPY requirements.txt /srv/app/
RUN pip3 install --no-cache-dir -r /srv/app/requirements.txt 



COPY config/nginx.conf /etc/nginx/nginx.conf
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY src /srv/app/
COPY config/uwsgi.ini /srv/app/

ENV UWSGI_INI /srv/app/uwsgi.ini
WORKDIR /srv/app/

ENTRYPOINT ["dumb-init", "--"]
EXPOSE 80