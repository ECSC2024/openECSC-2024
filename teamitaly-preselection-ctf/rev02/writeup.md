# TeamItaly Preselection CTF 2024

## [rev] crackme maybe (1 solves)

Can you find the correct input?

Author: Lorenzo Catoni <@lorenzcat>

## Overview

The binary wants a string passed as command line argument and after checking that is a valid hex string of lenght 16 it calls `FUN_0010198b` passing the provided input as argument, if this function return 0 it means the input is correct and the program exits with return code 0, otherwise exits with 1.

The function at `10198b` does the following (some parts omitted):

```c
undefined8 FUN_0010198b(char *param_1)

{
  /* declare vars */
  ...

  /* init bitmasklist[0:8] to hardcoded values */
  bitmasklist[0] = DAT_00105020;
  ...

  j = 0;
  do {
    if (0x3f < j) {
      /* success or fail exit condition based on value of bitmasklist[0:4] */
      return uVar1;
    }
 /* core part of the loop, calculate `key` from specific bits of param_1, 
  * bit positions specified by bitmasklist[i] */
    key = 0;
    for (i = j; i < j + 8; i = i + 1) {
      bit = 0;
      for (bitmask = bitmasklist[i - j]; bitmask != 0; bitmask = bitmask >> 1) {
        if ((bitmask & 1) != 0) {
          key = key ^ (byte)(((int)(uint)(byte)param_1[bit >> 3] >> ((byte)bit & 7) & 1U) <<
                            ((byte)i & 7));
        }
        bit = bit + 1;
      }
    }
 /* do something with `key` and some hardcoded data, write result inside bitmasklist[0:8] */
    FUN_00101864((long)&key,1,(long)(&DAT_00105020 + j + 8),(long)bitmasklist,8);
    if (j != 0x38) {
      /* if a condition on bitmasklist[0:8] is met continue looping otherwise exit with fail */
      if (/* fail condition */) {
        uVar1 = 1;
        goto LAB_00101bbf;
      }
    }
    j = j + 8;
  } while( true );
}
```

The function at 101864 as the following (some parts omitted):

```c
void FUN_00101864(char *key,int keylen,uint64_t *in,uint64_t *out,int len)
{
  /* declare vars */
  iv = 0;
  FUN_001013c0((long)local_1058,(long)key,keylen);
  for (i = 0; i < len; i = i + 1) {
    uVar1 = FUN_001015db(local_1058,in[i]);
    out[i] = uVar1 ^ iv;
    iv = in[i];
  }
  return;
}
```

This is the pattern of cbc decryption with iv hardcoded to all zeroes where `FUN_001015db` is a block cipher with blocks of 64 bits. By looking around and googleing some constants used in `FUN_001013c0`, they match with the ones of the Blowfish algorithm, this is indeed what this function does. `FUN_001013c0` is the functions that generates the internal state from the provided encryption/decryption key, notably, if the key is not long enought, the key is just repeated until it has a sufficient lenght. This will be useful later since the function is always called with keyLen = 1.

So to summarise the function that checks the input does the following:

1. Load bitmask list from memory
2. calculate key from input and bitmask list like so

```c
key = 0;
for (i = j; i < j + 8; i = i + 1) {
 bit = 0;
 for (bitmask = bitmasklist[i - j]; bitmask != 0; bitmask = bitmask >> 1) {
  if ((bitmask & 1) != 0) {
   key = key ^ ((param_1[bit >> 3] >> (bit & 7) & 1U) << (i & 7));
  }
 bit = bit + 1;
 }
}
```

3. decrypt the hardcoded data with the key (len=1) and store the result in bitmasklist[0:8]
4. check if bitmasklist matches a condition on the number of bits set to 1
5. repeat from step 2 until all 64 bits of the input are processed
6. on the last iteration check if bitmasklist is equal to some hardcoded values, if so return 0, otherwise return 1

If the function returns 0 the input value is used to decrypt the flag and print it.

## Solution

Since the decryption is done with a key of length 1, it possible to bruteforce all 256 possible values for the key and check if the decryption of the data results in a bitmask that passes the check on the number of bits set to 1. After that, knowing the bitmasks and the keys it is possible to recover the corrent input via (for example) z3.

## Exploit

```py
#!/usr/bin/env python3.10
import functools
from Crypto.Cipher import Blowfish
import sys

'''
# part one: recover plaintext and key pairs by bruteforcing
'''

# start address of enc bitmasks
bm_startaddr = 0x4020

with open(sys.argv[1], 'rb') as f:
    f.seek(bm_startaddr)
    enc_bms = [int.from_bytes(f.read(8), 'little') for _ in range(64+8)]

# find all keyes by bruteforcing
chunks = [enc_bms[i:i+8] for i in range(8, len(enc_bms), 8)]

pts = []
keys = []
for chunk in chunks[:-1]: # last chunk has a different condition (coffebabe..)
    for key in range(256):
        cipher = Blowfish.new(bytes([key])*4, Blowfish.MODE_CBC, iv=bytes(8))
        pt = cipher.decrypt(b"".join(c.to_bytes(8, 'big') for c in chunk))
        pt_chunk = [int.from_bytes(pt[i:i+8], 'big') for i in range(0, len(pt), 8)]
        ors = functools.reduce(int.__or__, pt_chunk)
        if ors.bit_count() <= 24: # hit
            break
    else:
        raise Exception("not found")
    
    pts.append(pt_chunk)
    keys.append(key)

# last chunk
for key in range(256):
    cipher = Blowfish.new(bytes([key])*4, Blowfish.MODE_CBC, iv=bytes(8))
    pt = cipher.decrypt(b"".join(c.to_bytes(8, 'big') for c in chunks[-1]))
    pt_chunk = [int.from_bytes(pt[i:i+8], 'big') for i in range(0, len(pt), 8)]
    if pt_chunk[0] == 0xdeadbeef: # one is enought
        break
else:
    raise Exception('not found')

keys.append(key)
pts.insert(0, enc_bms[:8]) # first one was already plaintext

'''
# stage two: recover flag with z3
'''

import z3

s = z3.Solver()
flag = [z3.BitVec(f"flag{i}", 8) for i in range(8)]

for pt, key in zip(pts, keys, strict=True):
    key_sym = 0
    for i, bitmask in enumerate(pt):
        bit = 0
        while bitmask:
            if bitmask & 1:
                key_sym ^= ((flag[bit // 0x8] >> (bit % 0x8)) & 1) << (i % 0x8)
            bitmask >>= 1
            bit += 1
    s.add(key_sym == key)

while s.check() == z3.sat:
    m = s.model()
    print(bytes([m[f].as_long() for f in flag]).hex())
    s.add(z3.Or([f != m[f] for f in flag])) # find all
```
