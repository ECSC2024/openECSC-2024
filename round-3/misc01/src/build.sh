set -e
set -x

rm -f disk.img

truncate disk.img -s 1M
mkfs -t vfat disk.img
mkdir -p ./mount
sudo mount -t vfat disk.img ./mount

sudo zip --password password ./mount/flag.zip ./flag.txt

sudo echo 'The password is: password' | sudo tee ./mount/zip-password.txt >/dev/null

sync
sleep 5
sudo rm -rf ./mount/flag.zip

sudo umount ./mount
rm -rf ./mount

binwalk ./disk.img
