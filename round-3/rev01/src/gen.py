#!/usr/bin/env python3
import os
import subprocess
import sys

userid = sys.argv[1]
flag_base = 'openECSC{d1g1t4L_cdm4_ju57_w0rk5_n0w_w3_g0_t0p_s3cr37!_%s}'


def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()


flag = gen_custom_flag()


def gen_attachment(path: str):
    out = subprocess.check_output(['./livestream', flag], stderr=subprocess.DEVNULL, cwd='src')
    with open(path, 'wb') as f:
        f.write(out)


gen_attachment(f'attachments/output.bin/{userid}')
print(flag)
