#!/bin/sh

timeout 600 qemu-system-x86_64 \
    -kernel ./bzImage \
    -cpu qemu64,+smep,+smap,+rdrand \
    -m 128M \
    -smp 4 \
    -initrd ./initramfs.cpio.gz \
    -append "console=ttyS0 quiet loglevel=3 oops=panic panic_on_warn=1 panic=-1 pti=on page_alloc.shuffle=1" \
    -monitor /dev/null \
    -serial mon:stdio \
    -nographic
