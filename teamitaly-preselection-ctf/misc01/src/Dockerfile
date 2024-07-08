FROM cybersecnatlab/socaz:alpine-3.19

RUN apk update && apk add --no-cache bash

WORKDIR /chall

COPY --chmod=755 server.bash /chall/server

CMD socaz --bind 1337 --flag-from-env FLAG -- /chall/server