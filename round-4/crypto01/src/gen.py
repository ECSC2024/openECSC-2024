#!/usr/bin/env python3
import os
import sys
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

userid = sys.argv[1]
flag_base = 'openECSC{nth_r00t_m4g1c_%s}'

def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()

flag = gen_custom_flag()

def gen_attachment(path: str):
    with open('src/key.pem', 'rb') as rf:
        key = RSA.import_key(rf.read())

    #generating with fixed key
    with open(path, 'w') as wf:
        n = key.n
        c = PKCS1_OAEP.new(key).encrypt(flag.encode()).hex()
        wf.write(f'{n = }\n{c = }')

gen_attachment(f'attachments/prettyprimes_output.txt/{userid}')
print(flag)
