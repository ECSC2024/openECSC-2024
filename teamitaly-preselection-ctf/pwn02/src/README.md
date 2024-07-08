[PWN] Pointer-Authenticated Calculator
======================================

A simple linear stack buffer overflow ARM64 challenge with PAC enabled. The
challenge itself also makes use of PACIA/AUTIA to sign/auth function pointers,
which can be abused to forge arbitrary signed pointers.

For simplicity, the challenge idea relies on a fixed (not randomized) stack,
which QEMU user AArch64 version 7.2 provides. Newer QEMU versions randomize the
stack, so they are a no-go.


Custom QEMU build
-----------------

QEMU's PAC implementation seems to only use 8 bits for PAC signatures in the top
VA bits of signed pointers. Such a small value makes the challenge prone to
simple brute-force solutions. QEMU seems to choose whether to use 16 or 8 bits
for PAC signatures through a bit in VCTR_EL2, which seems to always be set.

A small patch [`qemu-7.2.12.patch`](./qemu-7.2.12.patch) is provided to build a
custom QEMU version that ignores this bit and therefore produces 16 bit PAC
signatures that are less prone to bruteforce.


Building
--------

Simply run `make` to create `build/pac`, the binary for the challenge. You will
need an AArch64 compiler. Set `CC=` appropriately when running `make`. By
default, `CC=aarch64-linux-gnu-gcc`.

Run `make archive` to generate the final archive to distribute to players
directly inside `../attachments`.

The custom QEMU is automatically built by the Docker containre using the
provided [`Dockerfile`](./Dockerfile).
