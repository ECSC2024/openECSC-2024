#!/usr/bin/env python3

import logging
import os
from pwn import remote
import random
import string
import math
from sympy.ntheory.modular import crt 

logging.disable()

HOST = os.environ.get("HOST", "random-cycles.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38102))

alph = string.ascii_letters + string.digits
n = 50

def spin(w, n):
    n = n % len(w)
    return w[-n:] + w[:-n]

def decrypt(ct, key):
    pt = ct
    for i in range(n-1, 0, -1):
        k = key[pt[i-1]]
        pt = pt[:i] + spin(pt[i:], -k)
    return pt

chall = remote(HOST, PORT)

key = {x: [(0, 1)] for x in alph}

for _ in range(10):
    payload = ''.join(random.sample(alph, n))

    chall.sendlineafter(b": ", payload.encode())
    ans = chall.recvline().decode().split(": ")[1].strip()

    tmp = payload
    for i in range(n-2):
        k = n-i-1 - tmp[i+1:].index(ans[i+1])
        key[tmp[i]].append((k, n-i-1))
        tmp = tmp[:i+1] + spin(tmp[i+1:], k)

my_key = {x: int(crt([y[1] for y in key[x]], [y[0] for y in key[x]])[0]) % int(math.lcm(*[y[1] for y in key[x]])) for x in alph}

for _ in range(100):
    ct = chall.recvline().decode().split(": ")[1].strip()

    pt = decrypt(ct, my_key)
    chall.sendlineafter(b": ", pt.encode())

print(chall.recvline().decode())
