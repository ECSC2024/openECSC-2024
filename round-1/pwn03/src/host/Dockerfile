FROM ubuntu:jammy

RUN apt update -y && apt upgrade -y
RUN apt install qemu-system-ppc -y

RUN mkdir /chall
WORKDIR /chall

COPY ./run.sh .
RUN mkdir ./flag
COPY ./flag/.env ./flag
COPY ./debian-12-generic-ppc64el-20240211-1654.qcow2.ready ./debian-12-generic-ppc64el-20240211-1654.qcow2

RUN chmod 755 ./run.sh && chmod 644 ./flag/.env && chmod 666 ./debian-12-generic-ppc64el-20240211-1654.qcow2

RUN useradd user
USER user

CMD ["./run.sh"]
