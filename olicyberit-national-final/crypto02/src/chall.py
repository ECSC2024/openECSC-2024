#!/usr/bin/env python3

import os
import random

flag = os.getenv('FLAG', 'flag{redacted}')
flagn = int.from_bytes(flag.encode(), byteorder='big')

def gen_otp(n):
    bitlen = n.bit_length()
    r = random.randint(0, n)

    return (r^flagn) & ((1 << bitlen) - 1)

print('Welcome to the only ecnryption service that allows you to choose the range in which the OTP is chosen.')
print('The only drawback is that we will truncate the ciphertext in order to avoid leaking any information!')

while True:
    n = int(input('> '))
    print(gen_otp(n))