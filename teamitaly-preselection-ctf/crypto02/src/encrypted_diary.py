#!/usr/bin/env python3

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import lorem

flag = os.getenv('FLAG', 'TeamItaly{redacted}')

BLOCK_SIZE = AES.block_size

def xor(a, b):
    return bytes([x^y for x,y in zip(a,b)])

def next_tweak(tweak):
    tweak = int.from_bytes(tweak, "little")
    tweak = tweak << 1

    if tweak >> (8*16):
        tweak = tweak ^ 0x100000000000000000000000000000087

    return tweak.to_bytes(BLOCK_SIZE, "little")

def encrypt(tweak, pt, key1, key2):
    tweak = tweak.to_bytes(BLOCK_SIZE, "little")
    pt = pad(pt, BLOCK_SIZE)

    blocks = [pt[i:i+BLOCK_SIZE] for i in range(0, len(pt), BLOCK_SIZE)]

    tweak = AES.new(key2, AES.MODE_ECB).encrypt(tweak)

    cipher = AES.new(key1, AES.MODE_ECB)

    ct = b""

    for i, b in enumerate(blocks):
        ct_b = xor(b, tweak)
        ct_b = cipher.encrypt(ct_b)
        ct += xor(ct_b, tweak)
        tweak = next_tweak(tweak)
    
    return ct

def decrypt(tweak, ct, key1, key2):
    tweak = tweak.to_bytes(BLOCK_SIZE, "little")
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]

    tweak = AES.new(key2, AES.MODE_ECB).encrypt(tweak)

    cipher = AES.new(key1, AES.MODE_ECB)

    pt = b""

    for b in blocks:
        pt_b = xor(b, tweak)
        pt_b = cipher.decrypt(pt_b)
        pt += xor(pt_b, tweak)
        tweak = next_tweak(tweak)

    return unpad(pt, BLOCK_SIZE)

class EncryptedDiary:

    def __init__(self):
        self.diary = {}
        self.key1, self.key2 = [os.urandom(16)]*2
        admin_diary = [lorem.sentence().encode() for _ in range(10)] + [flag.encode()]
        userspace = (len(admin_diary)+1, len(admin_diary)+1)
        adminspace = (1, len(admin_diary)+1)
        self.save_space(userspace, adminspace)
        for i, l in enumerate(admin_diary):
            self.diary[i+1] = encrypt(i+1, l, self.key1, self.key2)

    def save_space(self, userspace, adminspace):
        space = b""
        for l in userspace + adminspace:
            space += l.to_bytes(BLOCK_SIZE//2, "little")
        enc_space = encrypt(0, space, self.key1, self.key2)
        self.diary[0] = enc_space
    
    def decode_space(self):
        dec_space = decrypt(0, self.diary[0], self.key1, self.key2)
        userspace = (int.from_bytes(dec_space[:BLOCK_SIZE//2], "little"), int.from_bytes(dec_space[BLOCK_SIZE//2:BLOCK_SIZE], "little"))
        adminspace = (int.from_bytes(dec_space[BLOCK_SIZE:BLOCK_SIZE//2*3], "little"), int.from_bytes(dec_space[BLOCK_SIZE//2*3:BLOCK_SIZE*2], "little"))
        return userspace, adminspace

    def read_enc_line(self):
        l = int(input("line: "))
        if l >= len(self.diary) or l < 0:
            print(f"You can read from 0 to {len(self.diary) - 1}!")
            return
        else:
            print(self.diary[l].hex())

    def readline(self):
        userspace, _ = self.decode_space()
        l = int(input("line: "))
        if l not in range(userspace[0], userspace[1]):
            print(f"You can only read from {userspace[0]} to {userspace[1] - 1}")
        else:
            line = decrypt(l, self.diary[l], self.key1, self.key2)
            print(line.hex())
    
    def writeline(self):
        userspace, adminspace = self.decode_space()
        content = bytes.fromhex(input("content: "))
        enc_line = encrypt(userspace[1], content, self.key1, self.key2)
        self.diary[userspace[1]] = enc_line
        userspace = (userspace[0], userspace[1]+1)
        self.save_space(userspace, adminspace)
    
    def modify_enc_line(self):
        l = int(input("line: "))
        content = bytes.fromhex(input("content (in hex): "))
        self.diary[l] = content


Diary = EncryptedDiary()
while True:
    print("""1) Write a line
2) Read a line
3) Read an encrypted line
4) Modify an encrypted line""")
    choice = int(input("> "))

    if choice == 1:
        Diary.writeline()
    elif choice == 2:
        Diary.readline()
    elif choice == 3:
        Diary.read_enc_line()
    elif choice == 4:
        Diary.modify_enc_line()