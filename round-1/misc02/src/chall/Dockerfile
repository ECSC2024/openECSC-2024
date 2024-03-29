FROM alpine:3.19 AS builder

RUN apk update && apk add gcc git musl-dev socat

RUN mkdir /build
COPY main.c /build
COPY tlse_patch.diff /build

WORKDIR /build
RUN git clone https://github.com/eduardsui/tlse.git

WORKDIR /build/tlse
# This patch fixes a bug in tlse which causes it not to see the certificate signature sometimes
RUN git apply --whitespace=fix ../tlse_patch.diff

WORKDIR /build
RUN gcc -o chall main.c -DTLS_AMALGAMATION

FROM cybersecnatlab/socaz:alpine-3.19

RUN adduser user --disabled-password

WORKDIR /home/user
COPY --from=builder /build/chall ./chall

COPY certs/rootCACert.pem /home/user/rootCACert.pem
COPY certs/flagsdistribution.com.pem /home/user/flagsdistribution.com.pem
COPY certs/flagsdistribution.com.key /home/user/flagsdistribution.com.key

USER user
ENTRYPOINT socaz -v --timeout 30 --flag-from-env FLAG --bind 1337 --cmd /home/user/chall