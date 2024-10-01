FROM cybersecnatlab/socaz:python-3.11-alpine AS socaz

FROM sagemath/sagemath@sha256:8d657a42f33a407b8dbc9a3cb5818cb6b4df8aacc7b291ba675132ee55d4db73

USER root

RUN mkdir chall
WORKDIR chall

COPY --from=socaz /usr/local/bin/socaz /usr/local/bin/
COPY ./chall.sage ./
COPY ./start.sh ./
COPY ./requirements.txt ./

RUN chmod +x ./start.sh
RUN sage -pip install -r requirements.txt

CMD ["./start.sh"]