#!/usr/bin/env python3

import logging
import os
from pwn import remote
from hashlib import sha256

logging.disable()

def h(m):
    return int.from_bytes(sha256(m).digest(), "big")

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

# For TCP connection
HOST = os.environ.get("HOST", "localhost")
PORT = int(os.environ.get("PORT", 38300))

r = remote(HOST, PORT)

pk = r.recvline()
n = int(pk.split()[-2][1:-1])
e = 65537

r.recvuntil(b"> ")
r.sendline(b"3")
r.recvuntil(b": ")
r.sendline(b"test")
r.recvuntil(b": ")
r.sendline(b"admin")
r.recvlines(2)
sig = r.recvline()
s1 = int(sig.split()[-2][1:-1])
s2 = int(sig.split()[-1][:-1])

# a*e - b*h("I am...") = -h("ACK")

to_forge = h(b"Verifying myself: I am admin on OliCyber.IT")
base = h(b"ACK")

g, c1, c2 = extended_gcd(e, -to_forge)
c1 *= -base
c2 *= -base
s1f = pow(s1, c2, n)
s2f = (s2*pow(s1, c1, n)) % n

r.recvuntil(b"> ")
r.sendline(b"2")
r.recvuntil(b": ")
r.sendline(b"admin")
r.recvuntil(b": ")
r.sendline(str(s1f).encode())
r.recvuntil(b": ")
r.sendline(str(s2f).encode())
print(r.recvline())

