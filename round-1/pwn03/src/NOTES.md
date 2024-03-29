Challenge structure
===================

```
docker compose (1) -> qemu-system-ppc64le -> docker compose (2) -> socaz -> challenge
```

## qemu powerpc64le vm
- the image for the powerpc qemu vm is the file `debian-12-generic-ppc64el-20240211-1654.qcow2.ready`, which contains the vm configured and ready to be deployed (see [Debian image log](#debian-image-log) for details on the vm setup)
- the vm contains all the files necessary to spwn the challenge, which are mirrored in the folder `qemu`.
- it also contains a fake flag file, which is used in case the qemu vm is started without the flag mount (shouldn't happen).
- the vm has two systemd services for setting up the challenge at startup:
  - flag.service: if the flag file is mounted, it copies it into the challenge folder (otherwise the fallback fake flag is used)
  - challenge.service: when docker is started, it starts docker compose (2)
- the docker container uses socaz to spwn the challenge at every connection

## docker compose (1)
- the files in the `host` folder are the ones used to start the challenge
- docker copies the qemu vm image, the script to run qemu and the folder with the real flag that is mounted as a drive with qemu

## connecting to the vm

- the qemu vm has port forwarding configured for ports
  - 5555:5555 (the chall)
  - 2222:22   (ssh)
  

Debian image log
================

all the steps executed inside the qemu vm are listed here for reproducibility

## setup

1. download the image at [https://cloud.debian.org/images/cloud/bookworm/20240211-1654/debian-12-generic-ppc64el-20240211-1654.qcow2](https://cloud.debian.org/images/cloud/bookworm/20240211-1654/debian-12-generic-ppc64el-20240211-1654.qcow2)
2. `virt-customize -a debian-12-generic-ppc64el-20240211-1654.qcow2 --root-password password:<new-password>`
3. `qemu-img resize debian-12-generic-ppc64el-20240211-1654.qcow2 +100G`
4. run the image with `vm/run.sh`

## debian-12-generic-ppc64el-20240211-1654.qcow2

```console
nano authorized_keys      # insert your ssh key
apt update -y && apt upgrade -y
apt install ca-certificates curl tmux -y
nano ~/.tmux.conf
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo   "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" |   tee /etc/apt/sources.list.d/docker.list > /dev/null
apt update -y
apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y
mkdir /root/powerpc
```

configured systemctl service to launch docker compose at startup.

1. `nano /etc/systemd/system/challenge.service`
```
[Unit]
Description=Challenge Service
Requires=docker.service flag.service
After=docker.service flag.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker compose -f /root/powerpc/docker-compose.yml up -d --build
ExecStop=/usr/bin/docker compose -f /root/powerpc/docker-compose.yml down -v
WorkingDirectory=/root/powerpc
Restart=no

[Install]
WantedBy=multi-user.target
```
2. `systemctl daemon-reload`
3. `systemctl enable challenge.service`

To start and stop the service:
- `systemctl start challenge.service`
- `systemctl stop challenge.service`

To disable the service:
- `systemctl disable challenge.service`

### mouting flag file

edited `/etc/fstab` file to mount the flag at startup:
```
/dev/sdb1 /mnt/flag vfat defaults,nofail 0 2
```

added `setup.sh` to copy the flag from the mount at startup. configured as a service:

```
[Unit]
Description=Flag Service
After=local-fs.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/root/powerpc/setup.sh
WorkingDirectory=/root/powerpc
Restart=no

[Install]
WantedBy=multi-user.target
```

uploaded all files in /root/powerpc:
```
- docker-compose.yaml
- setup.sh
- .env (fake flag)
- main
```
