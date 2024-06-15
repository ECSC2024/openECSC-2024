#!/bin/sh

CHALL=30elode

echo "[+] copying chall files"
mkdir $CHALL
cp -r build/$CHALL $CHALL
echo "[+] zipping files"
zip -r $CHALL.zip $CHALL
mv $CHALL.zip ../attachments
rm -rf $CHALL
echo "[+] done"