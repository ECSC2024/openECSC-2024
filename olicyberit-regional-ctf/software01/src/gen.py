#!/usr/bin/env python3
import os.path
from os import urandom
from shutil import move
from subprocess import check_output
from sys import argv


def gen_custom_flag(flag_base: str) -> str:
    return flag_base % urandom(4).hex()


def gen_attachment(path: str, flag: str):
    filler_content = """
        .section flag_{i}_{char}
        .byte 0x0
    """

    sections = "\n".join([filler_content.format(i=i, char=c) for i, c in enumerate(flag)])

    binary = f"""
       .intel_syntax noprefix
       {sections}

       .section .text

dummy:
       ret
    """
    with open("src/cusu.S", "w") as outfile:
        outfile.write(binary)

    check_output(["make", "section31"], cwd=os.path.dirname(__file__))
    move("src/section31", path)


def main():
    userid = argv[1]
    flag_base = 'flag{f3d3r4t10n-0f-th3-pl4n3ts-%s}'
    flag = gen_custom_flag(flag_base)
    print(flag)

    gen_attachment(f"attachments/section31/{userid}", flag)


if __name__ == '__main__':
    main()
