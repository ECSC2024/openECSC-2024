#!/usr/bin/env python3
import os
import sys
import json
import gmpy2

# This is a sample script for generating static challenges (no remote) with different flags.
# This script is called by an automated tool. It must accept a single argument of the user id and
# output the flag generated for that user. Additionally, it must generate the challenge for this flag (and user)
# and write it to 'attachments/<attachment_name>/<userid>'. This script is run from the challenge root.

userid = sys.argv[1]
flag_base = 'flag{y35_w3_kn0w_7h47_7h3r3_4r3_m0r3_l1n35_bu7_7h3_1mp0r75_d0n\'7_c0un7_%s}'



def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()


def gen_attachment(path: str):
    with open(path, 'w') as wf:
        wf.write(json.dumps([x + int(gmpy2.next_prime(x)) for x in flag.encode()]))


gen_attachment(f'attachments/next_output.txt/{userid}')
print(flag)
