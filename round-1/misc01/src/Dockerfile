FROM cybersecnatlab/socaz:python-3.11-alpine

RUN apk add tshark

COPY ./chall.py /home/user/chall
COPY ./capture.pcapng /home/user/capture.pcapng

CMD ["socaz", "--timeout", "90", "--flag-from-env", "FLAG", "--bind", "1337", "--cmd", "env PYTHONUNBUFFERED=1 /home/user/chall"]