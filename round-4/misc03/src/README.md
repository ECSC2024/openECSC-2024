```
sudo zpool create pool /dev/sdb

zfs list -H -o name -t snapshot | sudo xargs -n1 zfs destroy

sudo zfs set snapdir=visible pool

ls -al /pool/.zfs

cp ./fake_malware.py /pool/challenge/malware.py
```

/pool/challenge/32449.txt
b'Zk\xbf\xf1\xea\x1b\xfe\xd5\x0cL\x0f\xd6XwX\x84'
