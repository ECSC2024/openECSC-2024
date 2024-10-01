set -ex

pushd ./1kat
./build.sh
popd

mkdir -p ./source/rootfs/files
mkdir -p ./source_without_flag/rootfs/files
cp -r ./1kat/1kat ./source/rootfs/files/1kat
cp -r ./1kat/1kat ./source_without_flag/rootfs/files/1kat

cp ./ext4.img ./source/rootfs/files/ext4.img
chmod o-r ./source/rootfs/files/ext4.img
cp ./ext4.img ./source_without_flag/rootfs/files/ext4.img
chmod o-r ./source_without_flag/rootfs/files/ext4.img

pushd ./source
./make_rootfs.sh
popd

pushd ./source_without_flag
./make_rootfs.sh
popd

#docker compose up --build
