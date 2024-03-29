#!/bin/sh

echo "[+] starting qemu"
qemu-system-ppc64le debian-12-generic-ppc64el-20240211-1654.qcow2 -m 2G -monitor /dev/null  -serial mon:stdio -nographic -smp 2 -net nic -net user,hostfwd=tcp::5555-:5555,hostfwd=tcp::2222-:22 -drive file=fat:ro:./flag,id=shared,readonly=on
echo "[+] exiting"
