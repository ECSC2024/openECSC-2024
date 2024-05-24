#!/bin/bash

set -e

cat <<GLHF
Give me the base64-encoded ELF of your program.
Input "EOF" on an empty line when done.
GLHF

while read -r -n 256; do
	if [ "$REPLY" = "EOF" ]; then
		break
	fi

	echo "$REPLY"
done | base64 -d > tmp/exe

if [ "$(readelf -h tmp/exe 2>/dev/null | awk '/Class|Machine/ { printf $2 }')" != "ELF64RISC-V" ]; then
	echo 'This does not look like a 64-bit RISC-V ELF!'
	exit 1
fi

# The xv6 mkfs tool is quite picky with the paths...
(cd tmp; ln -sr ../user user; ../mkfs fs.img user/* exe)

# To debug:
#
#   - Uncomment the DEBUG= line below
#   - Uncomment the two commented lines in docker-compose.yml
#   - Restart the container with: docker compose up -d
#   - Connect to the challenge and let QEMU start
#   - On the host, run: gdb-multiarch -ex 'target remote :1338'

#DEBUG='-gdb tcp::1338'

exec qemu-system-riscv64 $DEBUG \
	-machine virt \
	-bios none \
	-kernel kernel \
	-m 128M \
	-smp 2 \
	-nographic \
	-monitor none \
	-global virtio-mmio.force-legacy=false \
	-drive file=tmp/fs.img,if=none,format=raw,id=x0 \
	-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
	-semihosting
