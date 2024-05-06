This chall has been compiled on a Ubuntu 20.04 docker container. For reproducibility:

```console
docker run --rm -it -v ./:/src ubuntu@sha256:80ef4a44043dec4490506e6cc4289eeda2d106a70148b74b5ae91ee670e9c35d /bin/bash
```

then 

```console
apt update && apt install gcc-9 make -y
cd src
useradd -m -s /bin/bash user
su user
make
```
and the built binary is in `build/chall`.

> the user part is just to avoid having the compiled binary be owned by root.

To run the challenge locally and exploit it, out of the container, patch the binary: `patchelf --set-interpreter libs/ld-linux-x86-64.so.2 --replace-needed libc.so.6 libs/libc.so.6 ./build/yet_another_guessing_game`.
