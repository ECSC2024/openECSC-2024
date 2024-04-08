#!/bin/sh

CHALL=age_calculator_pro

echo "[+] copying chall files"
mkdir $CHALL
cp -r build docker-compose.yml $CHALL
echo "[+] redacting flag"
sed -i "s/^\([[:space:]]*-\s*'FLAG=\).*/\1flag{fake_flag}'/" $CHALL/docker-compose.yml
echo "[+] zipping files"
zip -r $CHALL.zip $CHALL
mv $CHALL.zip ../attachments
rm -rf $CHALL
echo "[+] done"