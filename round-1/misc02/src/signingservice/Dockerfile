FROM cybersecnatlab/socaz:python-3.11-alpine

RUN apk update && apk add openssl

COPY signService.py /signService.py
COPY root /rootcerts

RUN chmod +x /signService.py
ENTRYPOINT socaz -v --timeout 30 --bind 1337 --cmd "python3 /signService.py"