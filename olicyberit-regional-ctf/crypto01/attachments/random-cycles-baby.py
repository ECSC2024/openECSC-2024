#!/usr/bin/env python3
import os
import random

flag = os.getenv('FLAG', 'flag{redacted}')

key = {x : random.randint(0, len(flag) - 1) for x in flag}

def spin(w, k):
    k = k % len(w)
    return w[-k:] + w[:-k]

def encrypt_or_hash(w, key):
    for i in range(1, len(w)):
        w = w[:i] + spin(w[i:], key[w[i-1]])
    return w

output = encrypt_or_hash(flag, key)

with open("output.txt", 'w') as wf:
    wf.write(f'{key = }\n')
    wf.write(f'{output = }\n')