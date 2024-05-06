#!/bin/sh

CHALL=the_wilderness

echo "[+] copying chall files"
mkdir -p $CHALL/build
cp docker-compose.yml $CHALL
cp Dockerfile $CHALL
cp run.sh $CHALL
cp build/$CHALL $CHALL/build
cp -r sde-external-9.33.0-2024-01-07-lin $CHALL
echo "[+] redacting flag"
sed -i "s/^\([[:space:]]*-\s*'FLAG=\).*/\1openECSC{fake_flag}'/" $CHALL/docker-compose.yml
echo "[+] zipping files"
zip -r $CHALL.zip $CHALL
mv $CHALL.zip ../attachments
rm -rf $CHALL
echo "[+] done"
