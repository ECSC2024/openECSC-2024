#!/usr/bin/env python3
import os
import sys
import random

# This is a sample script for generating static challenges (no remote) with different flags.
# This script is called by an automated tool. It must accept a single argument of the user id and
# output the flag generated for that user. Additionally, it must generate the challenge for this flag (and user)
# and write it to 'attachments/<attachment_name>/<userid>'. This script is run from the challenge root.

userid = sys.argv[1]
flag_base = 'flag{4pp4rently_1s_4n_encrypt1on_n0w_l3ts_s3e_1f_its_s3cure_%s}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()


def gen_attachment(path: str):

    key = {x : random.randint(0, len(flag) - 1) for x in flag}

    def spin(w, k):
        k = k % len(w)
        return w[-k:] + w[:-k]

    def encrypt_or_hash(w, key):
        for i in range(1, len(w)):
            w = w[:i] + spin(w[i:], key[w[i-1]])
        return w

    output = encrypt_or_hash(flag, key)

    with open(path, 'w') as wf:
        wf.write(f'{key = }\n')
        wf.write(f'{output = }\n')


gen_attachment(f'attachments/output.txt/{userid}')
print(flag)
