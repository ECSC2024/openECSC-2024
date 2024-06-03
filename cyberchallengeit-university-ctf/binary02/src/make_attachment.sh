#!/bin/sh

CHALL=shellcoder

echo "[+] copying chall files"
mkdir $CHALL $CHALL/build
cp docker-compose.yml $CHALL
cp build/$CHALL $CHALL/build
echo "[+] redacting flag"
sed -i "s/^\([[:space:]]*-\s*'FLAG=\).*/\1CCIT{fake_flag}'/" $CHALL/docker-compose.yml
echo "[+] zipping files"
zip -r $CHALL.zip $CHALL
mv $CHALL.zip ../attachments
# rm -rf $CHALL
echo "[+] done"
