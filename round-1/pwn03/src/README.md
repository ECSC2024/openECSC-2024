README
======

- the challenge runs inside a docker container in a powerpc64le virtual machine run with qemu.
- the `host` folder contains all the deploy file.
- change the vm root password with `virt-customize -a debian-12-generic-ppc64el-20240211-1654.qcow2.ready --root-password password:<new-password>` (from `guestfs-tools` package)
- run `docker compose up --build -d` to deploy the challenge locally.

- you can mount the qemu vm image to inspect the challenge files in the vm at `/root/powerpc`
    - `modprobe nbd max_part=8`
    - `qemu-nbd --connect=/dev/nbd0 debian-12-generic-ppc64el-20240211-1654.qcow2.ready`
    - `mount /dev/nbd0p1 /mnt`
    then
    - `umount /mnt`
    - `qemu-nbd --disconnect /dev/nbd0`
    - `rmmod nbd`
- the qemu vm has ssh server installed

- the challenge consists in pwning the `main` binary to get the file `flag` which is in the same folder. **everything else is out of scope**. all the other files are given just to let you debug locally with a setup identical to the remote one.
