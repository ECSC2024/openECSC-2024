#!/usr/bin/env python3
import os
import sys

userid = sys.argv[1]
output_file = f'attachments/crackme/{userid}'

import hmac
import hashlib
from Crypto.Cipher import Blowfish
from Crypto.Util.number import long_to_bytes, bytes_to_long
import subprocess
import stat
import shutil

target_encflag = [0xa944aec1fa69f65a, 0x00cc92bda750b866, 0xfd78df8d9d56b1d5, 0x734e67ffc25848f4, 0x0d00ee99da8b3af4,
                  0xf8b8fdb6f32a527a]
target_bms = [0x40020008000, 0x4a0000000000, 0x100840, 0x100000204, 0x6000001000, 0x200000000000108, 0x4100000020000,
              0x1000000040000010, 0x21bdcdbd9c57ea1e, 0x42892e109d2816c8, 0x69a4b0e183e87d09, 0xf3f63785a2fd5a6d,
              0x895a1dd2d9080fc6, 0xf888c564daaa742f, 0x5ffd9b9c33e8523d, 0x235a3f27383a552d, 0xaa04cd6c1162469b,
              0x592dd30a8fb5c43a, 0x5f79983555b8c0bf, 0x56f69efa62529d26, 0x2cab3685b93761fb, 0xd7ef31a570311757,
              0xfd71db6bb0f8e0e2, 0x84deac43d5cc2aee, 0x6fe9f5fdc92ae602, 0xe8df3cbdb77a6509, 0x9eba72f3be536219,
              0x22ba32b3df1087de, 0x547769661351eb97, 0x1ef7764438ff2955, 0xa7d40e8c68c61111, 0x415d05557dea74c5,
              0x92c9b0a340fc8b69, 0x46496d4c7e796f6c, 0x31b227a0583027fa, 0xf7dbefc7dc42e729, 0xe467731cf725120f,
              0x2579d1e4698e882c, 0x40eba97751741d71, 0x582d37e7412ad2a1, 0xa92f2a89b091ed3e, 0xcf7c467ed08e0d6,
              0x9f759e63beaf1ad4, 0xc21b258bfa50cc92, 0x33d1b5fc5d6ff8fb, 0x432fe9f468c25adb, 0x4812fa87904ee2d,
              0xec8306fdb9f75fb7, 0xf6f7e5140661d4ca, 0x6427a249bc4ae7da, 0xdeaf263a8d59dfd1, 0x868468b0657bc766,
              0xe197a276c4d3c569, 0xcad47abcedc1dce5, 0xeef8297b02449a77, 0x358c55d89c066288, 0xf1151232abe32be7,
              0x1f1127f616b62eda, 0xebb07f0234efac04, 0xb7940573199b9ff8, 0x388614f0f58c54f8, 0x818bbe6869125997,
              0xb42104358f7626f2, 0x3e3e6f2dbec31447, 0x2396473593d13bb4, 0x54417863f9820f4, 0xc16453d25592fafc,
              0x27f8ddbdc2f0b5bb, 0x4491b3b7711b007a, 0xef749ab07c9cb3a3, 0x21e452152184c697, 0xd9dd17cd34ea8604]

bms = [0x0000040020008000, 0x00004a0000000000, 0x0000000000100840, 0x0000000100000204, 0x0000006000001000,
       0x0200000000000108, 0x0004100000020000, 0x1000000040000010, 0x2000002040000000, 0x0200084000000000,
       0x8000100000200000, 0x0000000000810002, 0x8040200000000000, 0x4000000100000008, 0x0000040000180000,
       0x1000080010000000, 0x0000000600000800, 0x0008008000040000, 0x8000000000002200, 0x8000000000240000,
       0x0088008000000000, 0x0000000008000003, 0x0000010010000080, 0x0002004400000000, 0x0200000000000022,
       0x0001400000400000, 0x0001000080001000, 0x0400000000101000, 0x0800000200000040, 0x0000000400000060,
       0x0200100000020000, 0x0000000006002000, 0x1800000000008000, 0x0102000200000000, 0x0010000000410000,
       0x0480000000001000, 0x4000000200004000, 0x0400c00000000000, 0x0400800000004000, 0x0000410000008000,
       0x0000022000100000, 0x2040000000008000, 0x0000000000000484, 0x0400000000000201, 0x0400000000080004,
       0x4000001000000010, 0x2000010010000000, 0x00000000c8000000, 0x0008000800800000, 0x0401008000000000,
       0x4000440000000000, 0x0c10000000000000, 0x0000000014002000, 0x0012000000008000, 0x0003000000020000,
       0x0000000000040014, 0x0000004000004200, 0x0000000030040000, 0x8008200000000000, 0x0000010400000800,
       0x0000011000100000, 0x0020000000000210, 0x0000200000010800, 0x0002000001000200]
bms += [0xdeadbeef, 0xc0ffebabe, 0xbaad1337, 0] * 2

HKEY = b'~A*\xbf\xf5\xab:w\xd6@\x9a\xe8n\x16O\xdb'
token = hmac.new(HKEY, userid.encode(), hashlib.sha256).digest()[:8]

keys = []
for j in range(0, 64, 8):
    key = 0
    for i in range(j, j + 8):
        bit = 0
        row = bms[i]
        while row:
            # print(hex(row))
            if row & 1:
                # print(bit, i, hex(key))
                key ^= ((token[bit // 0x8] >> (bit % 0x8)) & 1) << (i % 0x8)
            row >>= 1
            bit += 1
    keys.append(key)
# print(hex(key))

# print([hex(k) for k in keys])

enc_bms = bms[:8]
for i, key in enumerate(keys):
    cipher = Blowfish.new(bytes((key,)) * 4, Blowfish.MODE_CBC, iv=bytes(Blowfish.block_size))
    msg = b''.join(long_to_bytes(bms[j], 8) for j in range((i + 1) * 8, (i + 2) * 8))
    enc = cipher.encrypt(msg)

    enc_bms.extend([bytes_to_long(enc[j:j + 8]) for j in range(0, len(enc), 8)])

# print(",".join([hex(x) for x in encrypted_m]))
flag = b"TeamItaly{h3re's_my_numb3r_so_" + token.hex().encode() + b"}\x00"
assert len(flag) % 8 == 0

cipher = Blowfish.new(token, Blowfish.MODE_CBC, iv=bytes(Blowfish.block_size))
enc_flag = cipher.encrypt(b''.join([flag[i:i + 8][::-1] for i in range(0, len(flag), 8)]))  # little endian shit
enc_flag = [enc_flag[i:i + 8] for i in range(0, len(enc_flag), 8)]

# substitute data in binary
with open('src/crackme', 'rb') as f:
    data = f.read()

# bitmasks
for d, n in zip(target_bms, enc_bms):
    assert data.count(d.to_bytes(8, 'little')) == 1
    # print(hex(data.index(d.to_bytes(8, 'little'))))
    data = data.replace(d.to_bytes(8, 'little'), n.to_bytes(8, 'little'))
# flag
for d, n in zip(target_encflag, enc_flag):
    assert data.count(d.to_bytes(8, 'little')) == 1
    data = data.replace(d.to_bytes(8, 'little'), n[::-1])

test_file = f'/tmp/{os.urandom(4).hex()}'
with open(test_file, 'wb') as f:
    f.write(data)

# *very* rudimentary correctness test
os.chmod(test_file, os.stat(test_file).st_mode | stat.S_IEXEC)  # chmod +x

output = subprocess.check_output([test_file, token.hex()], stderr=subprocess.DEVNULL)
assert output.strip() == flag.rstrip(b'\x00')

wrong_token = bytearray(token)
wrong_token[0] ^= 0x10
ret = subprocess.call([test_file, wrong_token.hex()], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
assert ret == 1

# move file to attachments dir and print uniq flag
shutil.move(test_file, output_file)
print(flag.rstrip(b'\x00').decode())
