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
# enc_bms = [0x40020008000,0x4a0000000000,0x100840,0x100000204,0x6000001000,0x200000000000108,0x4100000020000,0x1000000040000010,0x21bdcdbd9c57ea1e,0x42892e109d2816c8,0x69a4b0e183e87d09,0xf3f63785a2fd5a6d,0x895a1dd2d9080fc6,0xf888c564daaa742f,0x5ffd9b9c33e8523d,0x235a3f27383a552d,0xaa04cd6c1162469b,0x592dd30a8fb5c43a,0x5f79983555b8c0bf,0x56f69efa62529d26,0x2cab3685b93761fb,0xd7ef31a570311757,0xfd71db6bb0f8e0e2,0x84deac43d5cc2aee,0x6fe9f5fdc92ae602,0xe8df3cbdb77a6509,0x9eba72f3be536219,0x22ba32b3df1087de,0x547769661351eb97,0x1ef7764438ff2955,0xa7d40e8c68c61111,0x415d05557dea74c5,0x92c9b0a340fc8b69,0x46496d4c7e796f6c,0x31b227a0583027fa,0xf7dbefc7dc42e729,0xe467731cf725120f,0x2579d1e4698e882c,0x40eba97751741d71,0x582d37e7412ad2a1,0xa92f2a89b091ed3e,0xcf7c467ed08e0d6,0x9f759e63beaf1ad4,0xc21b258bfa50cc92,0x33d1b5fc5d6ff8fb,0x432fe9f468c25adb,0x4812fa87904ee2d,0xec8306fdb9f75fb7,0xf6f7e5140661d4ca,0x6427a249bc4ae7da,0xdeaf263a8d59dfd1,0x868468b0657bc766,0xe197a276c4d3c569,0xcad47abcedc1dce5,0xeef8297b02449a77,0x358c55d89c066288,0xf1151232abe32be7,0x1f1127f616b62eda,0xebb07f0234efac04,0xb7940573199b9ff8,0x388614f0f58c54f8,0x818bbe6869125997,0xb42104358f7626f2,0x3e3e6f2dbec31447,0x2396473593d13bb4,0x54417863f9820f4,0xc16453d25592fafc,0x27f8ddbdc2f0b5bb,0x4491b3b7711b007a,0xef749ab07c9cb3a3,0x21e452152184c697,0xd9dd17cd34ea8604]

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
    #print(hex(key))

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
#print(hex(key))
# print(pts)

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
                key ^= ((flag[bit // 0x8] >> (bit % 0x8)) & 1) << (i % 0x8)
            bitmask >>= 1
            bit += 1
    s.add(key_sym == key)

while s.check() == z3.sat:
    m = s.model()
    print(bytes([m[f].as_long() for f in flag]).hex())
    s.add(z3.Or([f != m[f] for f in flag])) # find all
