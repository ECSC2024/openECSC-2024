Create ext4 filesystem image (8MB)

```
dd if=/dev/zero of=ext4.img bs=4k count=2048
mkfs.ext4 -b 1024 -m 0 ext4.img
tune2fs -c0 -i0 ext4.img
```

FS Block size: `stat -fc %s .`
