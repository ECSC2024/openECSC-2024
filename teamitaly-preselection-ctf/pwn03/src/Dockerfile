FROM cybersecnatlab/challenge-jail@sha256:1288f3d4a50361af9cc664f52a36973256bb86e348d6b708989142d24ba7f79d

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y --no-install-recommends \
    qemu-system-x86

EXPOSE 1337