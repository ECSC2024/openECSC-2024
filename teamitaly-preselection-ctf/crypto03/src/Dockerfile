FROM cybersecnatlab/socaz:ubuntu-jammy AS socaz

FROM sagemath/sagemath@sha256:aeefedc716b4f475ddc5f8d8140dbb231868b8a2e5882044845c83d41d1014a5

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