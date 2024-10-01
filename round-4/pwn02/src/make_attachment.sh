#!/bin/sh

CHALL=middleout

echo "[+] copying chall files"
mkdir $CHALL
cp -r lib build docker-compose.yml middleout.c hendricks.h $CHALL
echo "[+] redacting flag"
sed -i "s/^\([[:space:]]*-\s*'FLAG=\).*/\1openECSC{fake_flag}'/" $CHALL/docker-compose.yml
echo "[+] zipping files"
zip -r $CHALL.zip $CHALL
mv $CHALL.zip ../attachments
rm -rf $CHALL
echo "[+] done"
