# these two are in common for all the chalenges.
# We need to install some packets in order to "simplify" some challenges
FROM ubuntu:22.04

# Base programs. Userfull for RCE-related challenges.
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y wget curl netcat dumb-init

RUN DEBIAN_FRONTEND="noninteractive" apt-get install -y python3 python3-pip
RUN DEBIAN_FRONTEND="noninteractive" apt-get install -y nginx supervisor \
 && pip3 install --no-cache-dir uWSGI==2.0.24 \
 && useradd -ms /bin/null web 

COPY requirements.txt /srv/app/
ENV HOME /home/web
RUN pip3 install --no-cache-dir -r /srv/app/requirements.txt
RUN playwright install-deps chromium
RUN su -s /bin/bash -c "playwright install chromium" web

COPY config/nginx.conf /etc/nginx/nginx.conf
COPY config/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY . /srv/app/
COPY ./flag.txt /flag.txt
COPY config/uwsgi.ini /srv/app/

ENV UWSGI_INI /srv/app/uwsgi.ini
WORKDIR /srv/app/

ENTRYPOINT ["dumb-init", "--"]
CMD ["/usr/bin/supervisord"]
EXPOSE 80