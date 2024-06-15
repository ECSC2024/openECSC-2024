#!/usr/bin/env python3
import os
import subprocess
import sys

# This is a sample script for generating static challenges (no remote) with different flags.
# This script is called by an automated tool. It must accept a single argument of the user id and
# output the flag generated for that user. Additionally, it must generate the challenge for this flag (and user)
# and write it to 'attachments/<attachment_name>/<userid>'. This script is run from the challenge root.

userid = sys.argv[1]

flag_base = 'flag{4i_b3_l1k3_%s}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()


def gen_attachment(path: str):
    subprocess.check_call(
        ["python3", "challenge.py", '../' + path],
        cwd='src',
        env={**os.environ, 'FLAG': flag},
    )
    os.rename(path + '.png', path)


gen_attachment(f'attachments/output.bin/{userid}')
print(flag)
