# Pointer-Authenticated Calculator

**DISCLAIMER**: This challenge uses a custom QEMU build to deter
bruteforce-based solutions. The provided `Dockerfile` will automatically build
`qemu-aarch64` version 7.2.12 after applying `qemu-7.2.12.patch`.
**This patch is out of scope for exploitation purposes!** It is only provided
for transparency and is not intended to introduce any vulnerability in QEMU. It
is possible to solve the challenge on both a patched and unpatched
`qemu-aarch64` 7.2.12 regardless.

If you wish to use the exact same QEMU binary locally, you can extract it after
building and starting the container:

```sh
docker compose up -d --build
docker cp pac:/usr/local/bin/qemu-aarch64 .
./qemu-aarch64 ./pac
```

## Debugging

To enable debugging for the challenge running under `qemu-aarch64` inside the
Docker container, uncomment all the commented lines in `docker-compose.yml` and
restart with `docker compose up -d`.

Once started, connect to the challenge and QEMU will wait for a debugger on port
1234 before starting. To connect to QEMU's GDB server you can then run the
following command from a different terminal:

```sh
gdb-multiarch -ex 'target remote :1234'
```

Use only one connection at a time when debugging. Multiple QEMU instances won't
be able to listen on the same debug port at the same time.
