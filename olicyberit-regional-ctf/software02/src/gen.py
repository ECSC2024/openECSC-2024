#!/usr/bin/env python3
import os
import sys
from subprocess import check_output
from shutil import move
from os import remove
from base64 import b64encode

# This is a sample script for generating static challenges (no remote) with different flags.
# This script is called by an automated tool. It must accept a single argument of the user id and
# output the flag generated for that user. Additionally, it must generate the challenge for this flag (and user)
# and write it to 'attachments/<attachment_name>/<userid>'. This script is run from the challenge root.


def gen_custom_flag(flag_base: bytes) -> bytes:
    return flag_base % os.urandom(4).hex().encode()


def gen_attachment(path: str, encoded_flag: bytes):
    flag_bytes = ",".join([hex(b) for b in encoded_flag])

    check_output(["make", f"FLAG={flag_bytes}"], cwd=os.path.dirname(__file__))
    move("src/ghost", path)


def rol(val, r_bits, max_bits):
    return (val << r_bits % max_bits) & (2**max_bits - 1) | \
        ((val & (2**max_bits-1)) >> (max_bits-(r_bits % max_bits)))


def encode_flag(flag: bytes):
    return b64encode(bytes([
        rol(c ^ 0b101010, 0b1010, 8) for c in flag
    ]))


def main():
    userid = sys.argv[1]
    flag_base = b'flag{gdb_1s_4ctuall1_us3ful_%s}\x00'
    flag = gen_custom_flag(flag_base)

    gen_attachment(f'attachments/ghost/{userid}', encode_flag(flag))
    print(flag.strip(b'\x00').decode())


if __name__ == '__main__':
    main()
