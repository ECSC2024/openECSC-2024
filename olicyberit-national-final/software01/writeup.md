# OliCyber.IT 2024 - National Final

## [rev] MIC (16 solves)

A Message In Code has just arrived for you Agent.

Author: Alberto Carboneri <@Alberto247>

## Overview

The challenge is composed of a single binary, asking the user for an input.
The input is then processed and checked to be equal with an hardcoded string.
If the check passes the user input is then xored with a static value stored in memory, producing the flag.

## Solution

The main part of the challenge is reversing the `check_key` function in order to produce the correct input from the available output.
There are two ways to achieve this: static and dynamic analisys.
The latter is the simpler, as the `check_key` function only scrambles the input without substituting any letter. We can therefore provide as input a string composed of unique characters, such as "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", analyze the memory at the strncmp function, and produce a map mapping each input character to its output position. Then by reversing this map and applying it to the hardcoded `encrypted_key` variable we can obtain the correct input.

The static approach, albeit more complicated, can be resolved by guessing the functions inner working from their name, with some help from a decompiler such as Ghidra.
- `format_key` formats our input into a square matrix of size 6x6 (the `grille` variable).
- `rotate_grille` rotates the `grille` variable by 90 degrees.
- `check_key` extracts specific characters from the `grille`, the rotates it, for 4 times.

By inverting the process we can recover the input from the provided output.

## Exploit

```python
from pwn import *

chall = ELF("./chall")

encrypted_key=chall.read(chall.symbols["encrypted_key"], 36).decode()
encrypted_flag=chall.read(chall.symbols["flag"], 36)

holes=[[0,1],[1,1],[1,3],[3,1],[3,3],[4,5],[5,0],[5,2],[5,3]] # Obtained from the binary

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

key = grille_encrypt(encrypted_key)
print(xor(encrypted_flag, key.encode()).decode())
```
