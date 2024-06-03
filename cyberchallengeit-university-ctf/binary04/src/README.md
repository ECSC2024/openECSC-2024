[PWN] Triwizard Maze
================

This is a blind challenge, no attachments are given to players. The actual
source code for the challenge is in [`src/`](./src).

Building
--------

Simply run `make` to create `build/triwizard-maze`, the binary for the
challenge.

To ensure the binary is easily dumpable from memory in its entirety, run
`make test`, which will try to dump the binary and run a couple of `readelf`
commands on it to show its sections and segments.

We want (see checks in [`dump_and_test.py`](./dump_and_test.py)):

- A LOAD section with offset 0x0 so that the \x7fELF magic is loaded in the
  first memory page (see output of readelf -l).
- ELF base and `.text` section at the address we want, plus with the same
  virtual offset and file offset.
- No holes between sections to make dumping the ELF easy, so all PROGBITS
  sections should be adjacent in memory (see output of readelf -S). We can allow
  holes only after all PROGBITS sections and before NOBITS (i.e. a hole after
  the program text/data/rodata and before bss).
