#!/usr/bin/env python3
import os
import sys
import subprocess

userid = sys.argv[1]
flag_base = 'flag{a_m1llion_trie5_is_e4sily_doabl3_%s}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()


def gen_attachment(path: str):
    with open(path, 'wb') as wf:
        env = dict(os.environ)
        env['FLAG'] = flag
        out = subprocess.check_output([sys.executable, "src/chall.py"], env=env)
        wf.write(out)


gen_attachment(f'attachments/ARXdesigner_output.txt/{userid}')
print(flag)
