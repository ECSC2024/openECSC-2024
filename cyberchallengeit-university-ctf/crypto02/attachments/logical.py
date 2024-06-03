#!/usr/bin/env python3

import os
from Crypto.Util.number import bytes_to_long
import random

flag = os.getenv('FLAG', 'CCIT{redacted}')
flag = bytes_to_long(flag.encode())

def encrypt(secret_key, note, n):
    res = secret_key
    for i in range(n):
        if note & 1:
            res ^= 1
        res = (res >> 2) | ((res & 3) << (2*n-2))
        note >>= 1
    return res

n = flag.bit_length()
secret_key = random.getrandbits(2*n)

enc_flag = encrypt(secret_key, flag, n)

enc_notes = [enc_flag]

while True:
    print()
    print("1) Encrypt note")
    print("2) Show encrypted notes")

    choice = int(input("> "))

    if choice not in [1, 2]:
        exit()
    elif choice == 1:
        note = bytes_to_long(input("Note: ").encode())
        enc_notes.append(encrypt(secret_key, note, n))
    elif choice == 2:
        for enc_note in enc_notes:
            print(enc_note)
