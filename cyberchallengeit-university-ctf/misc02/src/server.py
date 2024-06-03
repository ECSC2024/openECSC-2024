#!/usr/bin/env python3

import random
import string
import hashlib
import os
import sys
import base64

FLAG = os.getenv("FLAG", "Flag is missing, please contact an admin")


def xor(a, b):
    return bytes([x^y for x,y in zip(a,b)])


def verify(sig, cnt, chal):
    _s = hashlib.md5(str(cnt).encode() + bytes([(ord(c)-64)%256 for c in chal[:17]])).hexdigest()
    return sig == _s


key = bytes([22, 163, 9, 205, 30, 109, 176, 116, 171, 205, 149, 37, 244, 14, 183, 236, 163, 117, 79, 84, 154, 206, 45, 101, 255, 154, 219, 244, 145, 132, 173, 158])
chal = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(32))
print(chal)
hexd = hashlib.md5(xor(bytes([(ord(c)+64)%256 for c in chal]), key)).hexdigest()
resp = input().strip()

if resp != hexd:
    print('Authentication failed')
    exit()
print('Successfully authenticated')

file_contents = {
    'certificate.txt': 'This file is to certificate that its possessor is a real hacker.',
    'finalists.txt': 'The finalists of the 2024 edition of CyberChallenge.IT are: ***file is corrupted***.',
    'solution.txt': 'step 1: open the challenge; step 2: solve it; step 3: submit the flag.',
    'flag.txt': FLAG,
    }
available_files = list(file_contents.keys())

cnt = 0

while True:
    inp = input().strip()
    sys.stderr.write(repr(inp) + '\n')
    args = base64.b64decode(inp.encode()).decode().split(' ')

    sig = args[0]
    cmd = args[1]

    if not verify(sig, cnt, chal):
        print('Invalid signature')
        exit()
    
    print('Valid signature')
    cnt += 1

    match cmd:
        case 'list':
            print(len(available_files))
            for f in available_files:
                print(f)
 
        case 'get':
            filename = args[2]
            if filename not in available_files:
                print('File not found')
            else:
                print(file_contents[filename])
        
        case 'exit':
            exit()
        
        case _:
            print("Unkown command")
            exit()