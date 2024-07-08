# TeamItaly Preselection CTF 2024

## [rev] I forgot something (2 solves)

The given binary seems, at first glance, a random bunch of data.
First of all, trying to disassemble it, the first 256 bytes look ok, but then it looks like a random bunch of data insteaf of instructions. Disassembling the first part, we understand that this code modifies itself, xoring itself with `p64(0xdeadbeefdeadd0d0)`. After xoring it to another file, we start reversing again. Trying to disassemble it from the first byte, we see that there are some instructions that are effectively some no-ops but confuse a lot ghidra.

Namely the sequence of bytes

```text
0xe8, 0x06, 0x00, 0x00, 0x00, 0x48, 0x83, 0x04, 0x24, 0x08, 0xc3, 0xeb, 0xf8
```

is something like

```text
     call _1
_2:
     add qword ptr [rsp], 0x8
     ret
_1:
     jmp _2
_3:
```

These instructions effectively only push an address to the stack and in the end jump to `_3` with the `ret` instruction. If that value is never read (it isn't), these instructions are useless and are only a way to break the decompiler. In order to understand what is happening, they can be simply patched to `nop`s. This can be done manually using ghidra, or programmatically with a very simple script

```py
#!/usr/bin/env python3

BROKEN = bytes([0xe8, 0x06, 0x00, 0x00, 0x00, 0x48, 0x83, 0x04, 0x24, 0x08, 0xc3, 0xeb, 0xf8])


def main():
    with open("../src/forgot", "rb") as infile:
        content = infile.read()
    content = content.replace(BROKEN, b"\x90"*len(BROKEN))
    with open("./forgot_patched", "wb") as outfile:
        outfile.write(content)


if __name__ == '__main__':
    main()

```

Now that these instructions are patched away, we can understand what is happening. In pseudocode,

```c
build_something(buf1, buf2);

read(0, buf3, 0x80);
if (inlined_strncmp(buf1, buf3, 0x80) == 0) {
   exit(0);
} else {
   exit(1);
}

```

Using a bit of guessing, the program is reading a flag from stdin and saving it in `buf3`, computing the real flag and then comparing them. We can solve the challenge in the easy way and in the hard way. The hard way is to understand what the function `build_something` is doing and compute statically the flag. The simple way is to do some dynamic analysis. We can copy in memory this code and run it!

Setting a breakpoint in the right position will allow us to read the flag without understanding what the program is doing. In order to do so, we prepare another program

```c

int main(int argc, char* argv[]) {
  int offset;
  int fd;
  struct stat sb;

  if (argc != 3) fatal("./solve filename offset");

  offset = strtol(argv[2], NULL, 16);
  fd = open(argv[1], O_RDONLY);
  if (fd < 0) fatal("open");

  // Absolutely unnecessary, mapping a bigger size is sufficient.
  if (lstat(argv[1], &sb) == -1) fatal("stat");

  char* addr = (char*) mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE, fd, 0);
  if (addr == MAP_FAILED) fatal("mmap");

  void (*fun)() = addr + offset;

  asm volatile ("int3");
  fun();

  return 0;
}

```

In this snippet we are copying to an RWX memory region the original bunch of data and then jumping on it. We also set a breakpoint with the instruction `int3` just before running it, in order to make it simpler to debug.

Entering the shellcode, we can take note of the parameters given to the `build_something` function, just before the `call` instruction

```c
    0x7ffff7fc2013 4889df             <NO_SYMBOL>   mov    rdi, rbx
 -> 0x7ffff7fc2016 e845020000         <NO_SYMBOL>   call   0x7ffff7fc2260

   -> 0x7ffff7fc2260 53                 <NO_SYMBOL>   push   rbx
      0x7ffff7fc2261 4989f8             <NO_SYMBOL>   mov    r8, rdi
      0x7ffff7fc2264 4c8d9f80000000     <NO_SYMBOL>   lea    r11, [rdi + 0x80]




0x7ffff7fc2260 <NO_SYMBOL> (
   $rdi = 0x00007fffffffd660  ->  0x0000034000000340,
   $rsi = 0x00007ffff7fc2102  ->  0x6266726e707a6566 'fezpnrfbaj',
   $rdx = 0x00007ffff7fc2000  ->  0x000000fa358d4855,
   $rcx = 0x00007ffff7ec691c <mmap64+0x2c>  ->  0x7c77fffff0003d48 ('H='?),
   $r8 = 0x0000000000000003,
   $r9 = 0x0000000000000000
)

```

Notice that inside the function the flag is not computed at the address pointed by `rdi`, but `0x80` bytes later. With some simple gdb commands we can read the flag

```text
set $flag = $rdi + 0x80
ni
x/s $flag
```
