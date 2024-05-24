# openECSC 2024 - Round 3

## [misc] Deleted file (565 solves)

Oh no, I deleted a file. I need to get it back.

Author: Giovanni Minotti <@Giotino>

## Overview

We are given and attachment `disk.img` that is a disk image. We are told that a file was deleted and we need to recover it.

## Solution

Check which File System is used on the disk image:

```bash
$ file disk.img
disk.img: DOS/MBR boot sector, code offset 0x3c+2, OEM-ID "mkfs.fat", sectors/cluster 4, root entries 512, sectors 2048 (volumes <=32 MB), Media descriptor 0xf8, sectors/FAT 2, sectors/track 16, serial number 0xb0918da5, unlabeled, FAT (12 bit)
```

The file system is FAT12. We can use a forensic tool to recover the deleted file (e.g. `foremost`):

```bash
foremost -i disk.img -o output
```

It found a file called `flag.zip` in the output directory. Trying to extract it we are asked a password that we don't know.  
We can try to crack the password or we can simply check if there's something else on the disk image:

```bash
mkdir ./mountpoint
sudo mount -t vfat disk.img ./mountpoint
```

We can now check the files in the mounted directory:

```bash
$ ls -la ./mountpoint
total 22
drwxr-xr-x 2 root    root    16384 gen  1  1970 .
drwxrwxr-x 4 giotino giotino  4096 mag 11 10:17 ..
-rwxr-xr-x 1 root    root       26 mag 11 09:15 zip-password.txt

$ cat ./mountpoint/zip-password.txt
The password is: password
```

The password of the zip is `password` (it could have also been easly bruteforced). We can now extract the file:

```bash
unzip -P password ./mountpoint/flag.zip
```

It extract a file called `flag.txt` with the flag inside.

`openECSC{thank_you_for_recovering_my_file}`

## Alternative solution

`binwalk` can be used to recover the zip file from the image, but it extract a damaged file since it doesn't care about the File System.  
Software like `unzip` or `Windows Explorer` cannot be used since they are unable to parse the file, but `7z` or `7-Zip File Manager` work fine since 7-Zip does some magic that enables it to read a zip file without the entire file.

```bash
$ binwalk -e disk.img

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------


20992         0x5200          Zip archive data, encrypted at least v1.0 to extract, compressed size: 54, uncompressed size: 42, name: flag.txt
21206         0x52D6          End of Zip archive, footer length: 22
```

`7z` can be used to extract the file:

```bash
7z x _disk.img.extracted/5200.zip
```
