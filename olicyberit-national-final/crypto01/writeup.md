# OliCyber.IT 2024 - National Final

## [crypto] Next flag (64 solves)

Just an easy oneliner so that you can go to the next one quickly!

Author: Lorenzo Demeio <@Devrar>

## Overview

The challenge gives us an encoding system, where each character `x` is substituted with `x+next_prime(x)`.

## Solution

In order to reverse the encoding we can create a table with a character and its corresponding encoding. Note that this encoding is unique, since `x+next_prime(x)` is a strictly increasing function.

## Exploit

```py
import gmpy2
import json

sbox = [x+int(gmpy2.next_prime(x)) for x in range(256)]
flag = json.loads(open("next_output.txt").read())

res = ''

for el in flag:
    res += chr(sbox.index(el))

print(res)
```