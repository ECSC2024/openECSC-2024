.PHONY: main
main: main.c
	powerpc64le-linux-gnu-gcc main.c -o main -O0 -fno-stack-protector -static

run: main
	qemu-ppc64le -L /usr/powerpc64le-linux-gnu/ main

gdb: main
	qemu-ppc64le -g 1234 -L /usr/powerpc64le-linux-gnu/ main

attach:
	gdb-multiarch -ex "target remote :1234" -ex "c"
