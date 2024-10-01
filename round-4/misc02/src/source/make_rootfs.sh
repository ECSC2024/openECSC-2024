#!/bin/sh

# Copy all necessary files in the rootfs folder
cp rcS rootfs/etc/init.d/rcS
cp flag.txt rootfs/files                                  # Remember to redact this if you distribute the initramfs

cd rootfs
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
cd ..
