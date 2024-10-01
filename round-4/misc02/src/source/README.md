# Creating the challenge

## Make Linux kernel

https://phoenixnap.com/kb/build-linux-kernel

Requirements:

```bash
sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison
```

Get source code: **GIOTINO AGGIORNA LA VERSIONE QUI A UNA PIU RECENTEEEE**

```bash
mkdir src/linux
cd src/linux
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.10.tar.xz
tar xvf linux-6.10.tar.xz
rm linux-6.10.tar.xz
```

Make:

```bash
make clean
make -j4 x86_64_defconfig
````

```bash
make -j4
make headers

cp arch/x86/boot/bzImage /path/to/challenge
```

### Make rootfs

**GIOTINO AGGIORNA LA VERSIONE QUI A UNA PIU RECENTEEEE**

https://emreboy.wordpress.com/2012/12/20/building-a-root-file-system-using-busybox/
https://medium.com/@kiky.tokamuro/creating-initramfs-5cca9b524b5a


```bash
mkdir src/busybox
cd srcdeploy_allybox-1.35.0
```

```bash
make defconfig
make menuconfig
```
Settings –> "Build Options" and enable the option "Build BusyBox as a static binary"

```bash
make -j4 install
cp -r _install/* /path/to/challenge/rootfs
cd /path/to/challenge/
mkdir -p rootfs/etc/init.d
ln -fs bin/busybox rootfs/init
cp rcS rootfs/etc/init.d/rcS
```

## Run locally

```bash
./make_rootfs.sh
./run.sh
```
