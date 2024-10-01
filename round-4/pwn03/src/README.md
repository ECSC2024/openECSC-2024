[PWN] Backfired
===============

Entry level sandbox escape v8 challenge: pwn an Ignition bytecode backdoor.
Exploit strategy as seen in Google CTF 2023 Quals "v8box" and HITCON 2024 Quals
"v8sbx".


Building
--------

Simply run `make` to build v8 with Docker using
[`Dockerfile.v8build`](./Dockerfile.v8build). This will automatically apply the
patches in [`patches/`](./patches) and use the build config in
[`args.gn`](./args.gn). Output will be in the `dist/` directory. The only thing
we really care about is the final `dist/d8` binary. No `snapshot_blob.bin` is
needed because of `v8_use_external_startup_data=false`.

Run `make archive` to generate the final archive to distribute to players
directly inside [`../attachments`](../attachments).
