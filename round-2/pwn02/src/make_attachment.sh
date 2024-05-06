#!/bin/sh

CHALL=yet_another_guessing_game

echo "[+] copying chall files"
mkdir $CHALL
cp -r build libs docker-compose.yml $CHALL
echo "[+] redacting flag"
sed -i "s/^\([[:space:]]*-\s*'FLAG=\).*/\1openECSC{fake_flag}'/" $CHALL/docker-compose.yml
echo "[+] zipping files"
zip -r $CHALL.zip $CHALL
mv $CHALL.zip ../attachments
rm -rf $CHALL
echo "[+] done"
