#!/usr/bin/env python3
import os
import sys
from subprocess import check_output

# This is a sample script for generating static challenges (no remote) with different flags.
# This script is called by an automated tool. It must accept a single argument of the user id and
# output the flag generated for that user. Additionally, it must generate the challenge for this flag (and user)
# and write it to 'attachments/<attachment_name>/<userid>'. This script is run from the challenge root.

userid = sys.argv[1]
flag_base = 'CCIT{4ppaR3ntly_th31r_CrypT0_is_ju5t_Sn4k3_01l_%s}'
rng_bytes = 4

def tobase3(x):
    m = {0: 's', 1: 'S', 2: '5'}
    ret = ''
    while x:
        r = x%3
        x //= 3
        ret += m[r]
    return ret
        

def gen_custom_flag() -> str:
    return flag_base % tobase3(int.from_bytes(os.urandom(rng_bytes), 'big')).zfill(21).replace('0', 's')


flag = gen_custom_flag()


def gen_attachment(path: str):
    
    enc_flag = check_output(['python3', './src/SSSSSSSSSSSSSSSSSSSS.py'], env = {'FLAG': flag})

    with open(path, 'w') as wf:
        wf.write(enc_flag.decode())


gen_attachment(f'attachments/SSSSSSSSSSSSSSSSSSSS_output.txt/{userid}')
print(flag)
