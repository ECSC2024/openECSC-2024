#!/bin/sh

CHALL=array.xor

echo "[+] copying chall files"
mkdir $CHALL
cp -r dist wrapper.py v8.patch Dockerfile docker-compose.yml README.md $CHALL
echo "[+] redacting flag"
sed -i "s/^\([[:space:]]*-\s*'FLAG=\).*/\1openECSC{fake_flag}'/" $CHALL/docker-compose.yml
sed -i '/POW_BYPASS_HASH=/d' $CHALL/docker-compose.yml
sed -i '/POW_BITS=/d' $CHALL/docker-compose.yml
echo "[+] zipping files"
zip -r $CHALL.zip $CHALL
mv $CHALL.zip ../attachments
rm -rf $CHALL
echo "[+] done"
