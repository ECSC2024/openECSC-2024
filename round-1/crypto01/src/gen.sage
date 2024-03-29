#!/usr/bin/env sage

import os
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256


userid = sys.argv[1]
flag_base = 'openECSC{m4ybe_4_funny_n4m3_1s_n0t_en0ugh_f0r_s3curity_:(_%s}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()


def gen_attachment(path: str):
    a, b, a1, b1, key = load(os.path.join(os.path.dirname(__file__), 'key.sobj'))

    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(flag.encode(), AES.block_size))

    with open(path, 'w') as wf:
        wf.write(f"{a = }\n")
        wf.write(f"{b = }\n")
        wf.write(f"{b1 = }\n")
        wf.write(f"{a1 = }\n")
        wf.write(ciphertext.hex())


gen_attachment(f'./attachments/public.txt/{userid}')
print(flag)
