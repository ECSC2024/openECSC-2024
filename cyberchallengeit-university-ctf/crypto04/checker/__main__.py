#!/usr/bin/env python3

import itertools
import logging
import os
import random
import subprocess
from hashlib import md5
from math import gcd

from Crypto.Util.number import bytes_to_long
from pwn import remote

logging.disable()

HOST = os.environ.get("HOST", "cookielogin.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38200))


class Multicollision_MD5:
    def __init__(self, n_blocks, prefix, dir_path):
        self.n_blocks = n_blocks
        self.dir_path = dir_path
        self.blocks = []
        self.to_create = True
        if not os.path.isdir(self.dir_path):
            os.mkdir(self.dir_path)
        if not os.path.isfile(f"{self.dir_path}/prefix") or not open(f"{self.dir_path}/prefix", "rb").read() == prefix:
            with open(f"{self.dir_path}/prefix", "wb") as wf:
                wf.write(prefix)
        # Check if blocks already exist
        elif all(os.path.isfile(f"{self.dir_path}/block_{i}_{j}") for i in range(n_blocks) for j in range(2)):
            self.to_create = False

    def fastcoll(self, block_id):
        if block_id == 0:
            finp = f"{self.dir_path}/prefix"
        else:
            finp = f"{self.dir_path}/msg_{block_id - 1}_0"

        fout_0 = f"{self.dir_path}/msg_{block_id}_0"
        fout_1 = f"{self.dir_path}/msg_{block_id}_1"
        subprocess.run(["md5_fastcoll", "-p", finp, "-o", fout_0, fout_1])

    def create_blocks(self):
        if self.to_create:
            # Creating prefix collisions
            for block_id in range(self.n_blocks):
                print(f"[+] Block {block_id}")
                self.fastcoll(block_id)

            # Creating single blocks
            prev_len = 0
            for i in range(self.n_blocks):
                for j in range(2):
                    with open(f"{self.dir_path}/msg_{i}_{j}", "rb") as f:
                        msg = f.read()
                        self.blocks.append(msg[prev_len:])
                prev_len = len(msg)

            # Saving blocks
            for i in range(self.n_blocks):
                for j in range(2):
                    with open(f"{self.dir_path}/block_{i}_{j}", "wb") as f:
                        f.write(self.blocks[2 * i + j])
        else:
            for i in range(self.n_blocks):
                for j in range(2):
                    with open(f"{self.dir_path}/block_{i}_{j}", "rb") as f:
                        self.blocks.append(f.read())

    def get_collisions(self):
        if len(self.blocks) == 0:
            self.create_blocks()

        for block_idxs in itertools.product([0, 1], repeat=self.n_blocks):
            msg = b"".join(self.blocks[i * 2 + block_idxs[i]] for i in range(self.n_blocks))
            yield msg


def legendre(h, p):
    if h % p == 0:
        return 0
    elif pow(h, (p - 1) // 2, p) == 1:
        return 1
    else:
        return -1


def hash_msg(m):
    return bytes([0xbb] * 90) + os.urandom(2) + bytes([0xba]) + md5(m).digest() + bytes([0xcc])


def create_cookie(p, q, c, n, user):
    mask = random.randint(2, n - 2)
    inv_mask = pow(mask, -1, n)
    mask = pow(mask, 2, n)
    h = bytes_to_long(hash_msg(user)) * mask

    if legendre(h, p) * legendre(h, q) != 1:
        h = h // 2

    v1 = pow(h, (p + 1) // 4, p)
    v2 = pow(h, (q + 1) // 4, q)
    s = (q * ((c * (v1 - v2)) % p) + v2) % n
    s = s * inv_mask % n
    return min(s, n - s)


def register_user(user):
    chall.sendlineafter(b"> ", b"1")
    chall.sendlineafter(b": ", user.hex().encode())
    cookie = int(chall.recvline().decode().split(": ")[1])
    return cookie


def login_admin(p, q, n):
    user = b"admin"
    c = pow(q, -1, p)
    cookie = create_cookie(p, q, c, n, user)
    chall.sendlineafter(b"> ", b"2")
    chall.sendlineafter(b": ", user.hex().encode())
    chall.sendlineafter(b": ", str(cookie).encode())
    print(chall.recvline().decode())


# with process(["python", "test.py"]) as chall:
with remote(HOST, PORT) as chall:
    n = int(chall.recvline().decode().split(" = ")[1])
    multicoll = Multicollision_MD5(12, b"", os.path.join(os.path.dirname(__file__), "Blocks"))
    vals = []
    for user in multicoll.get_collisions():
        cookie = register_user(user)
        for s in vals:
            hope = gcd(s + cookie, n)
            if hope != 1 and hope != n:
                p = hope
                q = n // hope
                login_admin(p, q, n)
                exit()
        vals.append(cookie)
