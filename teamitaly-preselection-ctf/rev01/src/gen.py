#!/usr/bin/env python3
from random import choice, seed
from string import ascii_uppercase
from sys import argv
from pathlib import Path
from subprocess import run, DEVNULL
from itertools import repeat, chain
from os import urandom
from shutil import copyfile


DIR = Path(__file__).parent


def vigenere_encrypt(string, key):
    cipher_text = []
    for s, k in zip(string, chain.from_iterable(repeat(key))):
        if not 'a' <= s <= 'z':
            cipher_text.append(s)
            continue

        x = ((ord(s) + ord(k) - 2*ord('a')) % 26) + ord('a')
        cipher_text.append(chr(x))
    return "". join(cipher_text)


def vigenere_decrypt(string, key):
    cipher_text = []
    for s, k in zip(string, chain.from_iterable(repeat(key))):
        if not 'a' <= s <= 'z':
            cipher_text.append(s)
            continue

        x = ((ord(s) - ord(k)) % 26) + ord('a')
        cipher_text.append(chr(x))
    return "". join(cipher_text)


def bytes_to_format(arr: bytes):
    return ", ".join([
        f"{b:#04x}" for b in arr
    ])


def generate_custom_flag(userid: str):
    return "TeamItaly{secret_for_revving:do_not_rev_%s}" % urandom(4).hex()


def modify_flag(flag: bytes, key: bytes):
    for _ in range(3):
        flag = vigenere_encrypt(flag, key)
    flag = flag.encode()
    arr = []
    for i in range(len(flag)):
        arr.append(flag[i])
        arr.append(choice(ascii_uppercase).encode()[0])
    return arr


def main():
    userid = argv[1]
    seed(0xdeadbeef)
    key = "fezpnrfbaj"
    flag = generate_custom_flag(userid)
    arr = modify_flag(flag, key)

    with open(str(DIR / "main_template.S"), "r") as infile:
        content = infile.read()
    content = content.format(
        flag=bytes_to_format(arr),
        key=bytes_to_format(key.encode()),
    )
    with open(str(DIR / "main.S"), "w") as outfile:
        outfile.write(content)
    run(["make", "forgot"], check=True, cwd=str(DIR), stdout=DEVNULL, stderr=DEVNULL)
    directory = DIR.parent / "attachments" / "forgot"
    directory.mkdir(parents=True, exist_ok=True)
    copyfile(str(DIR / "forgot"), str(directory / userid))
    print(flag)
    # run(["make", "clean"], check=True, cwd=str(DIR))


if __name__ == '__main__':
    main()
