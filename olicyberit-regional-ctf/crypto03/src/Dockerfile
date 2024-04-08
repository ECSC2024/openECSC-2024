FROM cybersecnatlab/socaz:python-3.11-alpine

COPY ./random-cycles.py /home/user/chall

CMD socaz --timeout 30 --flag-from-env FLAG --bind 1337 --cmd /home/user/chall