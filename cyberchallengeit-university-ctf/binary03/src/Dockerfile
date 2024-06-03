FROM cybersecnatlab/socaz:ubuntu-jammy

RUN adduser user

CMD socaz --timeout 30 -u 1000 -g 1000 --flag-from-env FLAG --bind 31336 --cmd /home/user/chall
