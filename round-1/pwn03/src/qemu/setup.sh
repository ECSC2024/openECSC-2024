#!/bin/sh

FLAG=/mnt/flag/.env
DEST=/root/powerpc/

if [ -e $FLAG ]; then
    echo "[+] found mounted flag"
    cp $FLAG $DEST
else
    echo "[-] no mounted flag"
fi
