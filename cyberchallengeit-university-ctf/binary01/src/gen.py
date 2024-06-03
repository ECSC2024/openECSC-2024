#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import random
import string
import sys
import os

userid = sys.argv[1]
flag_base = 'CCIT{th1s_messag3_will_self_encryp7_in_3_2_1_%s}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()

_flag = flag.encode()


def gen_attachment(path: str):
    k = list(_flag)
    checkvalue = [256 - x for x in k]
    _k = ''.join([chr(c) for c in k])

    with open('src/chall.c.template', 'r') as f:
        template = f.read()

    template = template.replace('CHECKVALUE', str(checkvalue).replace('[', '{').replace(']', '}'))
    template = template.replace('LEN', str(len(flag)))

    with open('chall.c', 'w') as f:
        f.write(template)

    os.system(f'gcc chall.c -o {path}')


gen_attachment(f'attachments/CCIA/{userid}')
print(flag)
