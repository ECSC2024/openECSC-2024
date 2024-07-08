FROM cybersecnatlab/challenge-jail@sha256:a90fb2f6c9b460b8ed559bf78d5cbd084bff11fda5feb863229ec51d58641871

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
	apt-get install -y binutils gcc make git python3 ninja-build pkg-config libglib2.0-dev && \
	apt-get clean

# Get QEMU 7.2.12
WORKDIR /
RUN git clone --depth 1 --single-branch --branch v7.2.12 'https://github.com/qemu/qemu'

# Patch and build QEMU
WORKDIR /qemu
RUN --mount=type=bind,source=qemu-7.2.12.patch,target=qemu-7.2.12.patch \
	patch -p1 < qemu-7.2.12.patch
RUN ./configure --target-list=aarch64-linux-user --static --disable-tools \
	--disable-debug-info --disable-slirp --disable-lto --disable-werror \
	--disable-plugins
RUN make -C build -j install
RUN rm -rf /qemu

WORKDIR /home/user
