#!/usr/bin/env python3

from pwn import remote
import logging
import os

logging.disable()

HOST = os.environ.get("HOST", "encrypteddiary.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38312))

BLOCK_SIZE = 16

def xor(a, b):
    return bytes([x^y for x,y in zip(a,b)])

def read_enc_line(l):
    chall.sendlineafter(b"> ", b"3")
    chall.sendlineafter(b": ", str(l).encode())
    enc_l = bytes.fromhex(chall.recvline().decode())
    return enc_l

def write_enc_line(l, content):
    chall.sendlineafter(b"> ", b"4")
    chall.sendlineafter(b": ", str(l).encode())
    chall.sendlineafter(b": ", content.hex().encode())

def readline(l):
    chall.sendlineafter(b"> ", b"2")
    chall.sendlineafter(b": ", str(l).encode())
    return chall.recvline().decode().strip()

def writeline(content):
    chall.sendlineafter(b"> ", b"1")
    chall.sendlineafter(b": ", content.hex().encode())

with remote(HOST, PORT) as chall:
    enc_space = read_enc_line(0)
    new_enc_space = b"\x00"*16 + enc_space[16:]
    write_enc_line(0, new_enc_space)
    l = readline(0)
    u1 = int(l.split()[-3])
    u2 = int(l.split()[-1]) + 1
    tweak0 = u1.to_bytes(BLOCK_SIZE//2, "little") + u2.to_bytes(BLOCK_SIZE//2, "little")
    write_enc_line(0, enc_space)

    writeline(b"A"*32)
    enc_line = read_enc_line(12)
    write_enc_line(12, b"\x00"*16 + enc_line[16:])
    tweak12 = xor(bytes.fromhex(readline(12))[:16], (12).to_bytes(BLOCK_SIZE, "little"))

    write_enc_line(0, enc_space)

    wanted = (1).to_bytes(BLOCK_SIZE//2, "little") + (12).to_bytes(BLOCK_SIZE//2, "little")
    payload = xor(wanted, xor(tweak0, tweak12))
    writeline(payload)
    ct12 = read_enc_line(12)[:16]

    ct0 = xor(ct12, xor(tweak0, tweak12))
    write_enc_line(0, ct0 + enc_space[16:])

    print(bytes.fromhex(readline(11)).decode())