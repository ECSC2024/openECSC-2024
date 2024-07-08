# Readme

> **IMPORTANT NOTE**: there is an additional file you need to run the challenge, which is not in this repo because it is very big. Download it from [this link](https://cloud.cybersecnatlab.it/s/gQFbxWwFNokEaYJ) and place it in this folder.

You can login in the vm with `user:user`.  
In case your copy-paste inside qemu is broken, you can use the provided `freebsd.debug.qcow2` to supply an ext2 disk via qemu to push the exploit source in the vm.  
```
truncate -s 16M disk.img
mkfs.ext2 disk.img
sudo mount -o loop -t ext2 disk.img ./mnt
sudo cp exploit.c ./mnt/
sudo umount ./mnt
```
Then add `-hdb disk.img` to the qemu cmdline in `run.sh`.  
`disk.img` will be automatically mounted at `/home/user/exploit`.  
You can compile your exploit in the vm using `cc`.  

In the remote instance the flag will be inside an ext2 disk at `/dev/ada1`.