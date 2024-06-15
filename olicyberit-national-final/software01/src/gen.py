#!/usr/bin/env python3
import subprocess

import random
import string
import sys
import os
from textwrap import wrap

def xor(s1,s2):
    return bytes([ord(s1[i])^ord(s2[i]) for i in range(len(s1))])

userid = sys.argv[1]
flag_base = 'flag{de4d_dr0p_l0c4tion:ILO_%s}'
holes=[[0,1],[1,1],[1,3],[3,1],[3,3],[4,5],[5,0],[5,2],[5,3]]


def grille_decrypt(data):
    matrix=[list(data[:6]),list(data[6:12]),list(data[12:18]),list(data[18:24]),list(data[24:30]),list(data[30:])]
    out=""
    for x in range(4):
        for y in range(9):
            out+=matrix[holes[y][0]][holes[y][1]]
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
    return out

def grille_encrypt(data):
    matrix=[[0,0,0,0,0,0],[0,0,0,0,0,0],[0,0,0,0,0,0],[0,0,0,0,0,0],[0,0,0,0,0,0],[0,0,0,0,0,0]]
    ctr=0
    for x in range(4):
        for y in range(9):
            matrix[holes[y][0]][holes[y][1]]=data[ctr]
            ctr+=1
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
    return "".join(["".join(x) for x in matrix])

def gen_custom_flag() -> str:
    return flag_base % os.urandom(4).hex()[:7]

flag = gen_custom_flag()
secret = ''.join(random.choices(string.ascii_uppercase + string.digits, k=36))
#print(secret)
flag_encrypted = xor(flag, secret).hex()
flag_encrypted = "".join(["\\x"+c for c in wrap(flag_encrypted,2)])
decrypted_secret=grille_decrypt(secret)
assert grille_encrypt(decrypted_secret)==secret, "Not equal"

def gen_attachment(path: str):
    with open('src/chall.c.template', 'r') as f:
        template = f.read()

    template = template.replace('CHECKVALUE', decrypted_secret)
    template = template.replace('FLAG', flag_encrypted)

    with open('src/chall.c', 'w') as f:
        f.write(template)

    subprocess.check_output(['gcc', 'chall.c', '-o', '../'+path], cwd='src')


gen_attachment(f'attachments/MIC/{userid}')
print(flag)