FROM cybersecnatlab/challenge-jail@sha256:a90fb2f6c9b460b8ed559bf78d5cbd084bff11fda5feb863229ec51d58641871

ARG GCC_RISCV_VERSION=10.2.0-0ubuntu1
ARG XV6_COMMIT=f5b93ef12f7159f74f80f94729ee4faabe42c360

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
	apt-get install -y \
		gcc-riscv64-unknown-elf=$GCC_RISCV_VERSION \
		gcc make wget unzip patch \
		qemu-system-riscv64 && \
	apt-get clean

USER user

# Get xv6 source code
WORKDIR /home/user
RUN wget -O xv6.zip "https://github.com/mit-pdos/xv6-riscv/archive/$XV6_COMMIT.zip"
RUN unzip xv6.zip && mv xv6-riscv-$XV6_COMMIT xv6-riscv && rm xv6.zip

# Patch and build xv6
WORKDIR /home/user/xv6-riscv
RUN --mount=type=bind,source=chall.patch,target=chall.patch \
	patch -p1 < chall.patch
RUN make -j TOOLPREFIX=riscv64-unknown-elf- kernel/kernel fs.img

# Verify build
RUN --mount=type=bind,source=checksums.txt,target=checksums.txt \
	sha256sum --check checksums.txt

# Keep the bare minimum
RUN mv kernel/kernel mkfs/mkfs .. && \
	mkdir ../user && \
	bash -c 'mv user/_{cat,echo,grep,init,kill,ln,ls,mkdir,rm,sh,wc} ../user'

WORKDIR /home/user
RUN rm -rf xv6-riscv

USER root
