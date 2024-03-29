#!/bin/bash

echo "[+] copying files to attachments"
cd ..

rm src/rovermaster.tar.gz
mkdir -p attachments/host
cp src/host/* attachments/host/                              # flag won't be copied cause -r is omitted
mkdir attachments/host/flag
cp src/qemu/.env attachments/host/flag/                      # copy fake flag
cp src/README.md attachments/

echo "[+] zipping files"
cd attachments
tar --transform='s|^|rovermaster/|' -czvf ../rovermaster.tar.gz *
cd ..
rm -rf attachments
mv rovermaster.tar.gz src/
cd src

echo "[+] done"

