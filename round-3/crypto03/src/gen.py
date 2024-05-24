#!/usr/bin/env python3
import os
import sys
from Crypto.Util.number import getPrime, isPrime, long_to_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from hashlib import sha256

# This is a sample script for generating static challenges (no remote) with different flags.
# This script is called by an automated tool. It must accept a single argument of the user id and
# output the flag generated for that user. Additionally, it must generate the challenge for this flag (and user)
# and write it to 'attachments/<attachment_name>/<userid>'. This script is run from the challenge root.

userid = sys.argv[1]
flag_base = 'openECSC{kn0wn_d1ff3r3nc3_0f_a_m34ns_kn0wn_d1ff3r3nc3_0f_sh4r3d_%s}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()


def gen_attachment(path: str):
    p = getPrime(160)
    q = (p-1)//2
    while not isPrime(q):
        p = getPrime(160)
        q = (p-1)//2

    g = 2
    while pow(g, q, p) != 1:
        g += 1

    with open("src/secret_a_b.txt") as rf:
        a = int(rf.readline())
        b = int(rf.readline())

    assert a.bit_length() == b.bit_length() == 128

    a_digits = [int(d) for d in str(a)]

    ga = pow(g, a, p)
    gb = pow(g, b, p)
    shared = pow(ga, b, p)

    a1_digits = [(d + 1) % 10 for d in a_digits]
    a1 = int(''.join(map(str, a1_digits)))

    new_shared = pow(gb, a1, p)

    key = sha256(long_to_bytes(new_shared)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    enc_flag = cipher.encrypt(pad(flag.encode(), AES.block_size)).hex()

    with open(path, 'w') as wf:
        wf.write(f"{p = }\n")
        wf.write(f"{ga = }\n")
        wf.write(f"{gb = }\n")
        wf.write(f"{shared = }\n")
        wf.write(f"{enc_flag = }\n")


gen_attachment(f'attachments/lazydh.txt/{userid}')
print(flag)
