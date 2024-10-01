#!/usr/bin/env python3
import os
import subprocess
import sys

userid = sys.argv[1]
flag_base = 'openECSC{NTRU_broadcast_t0olbox_%s}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()


def gen_attachment(path: str):
    my_dir = os.path.abspath(os.path.dirname(__file__))
    chall = os.path.join(my_dir, "chall.py")
    with open(path, 'w') as wf:
        subprocess.check_call(["sage", "-python", chall], stdout=wf, env=os.environ | {"FLAG": flag})


gen_attachment(f'attachments/output_chameleon.txt/{userid}')
print(flag)
