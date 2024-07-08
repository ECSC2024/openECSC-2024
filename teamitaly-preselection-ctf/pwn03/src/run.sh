#!/bin/sh

flag=$(cat /home/user/flag)
cat /home/user/flag.template.ext2 | sed "s/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/${flag}/g" > /tmp/flag.ext2

qemu-system-x86_64 \
	-cpu qemu64,+smap,+smep \
	-smp 1 \
	-m 512M \
	-hda /home/user/freebsd.qcow2 \
	-hdb /tmp/flag.ext2 \
	-monitor none \
	-nographic \
	-no-reboot \
	-snapshot
