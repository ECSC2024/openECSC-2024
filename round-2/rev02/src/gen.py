#!/usr/bin/env python3
import os
import sys
import struct
from PIL import Image
from PIL import ImageDraw
import numpy as np


def gen_custom_flag(flag_base: bytes) -> bytes:
    return flag_base % os.urandom(4).hex().encode()


def make_output(flag):
    img = Image.new('L', (128, 64))
    draw = ImageDraw.Draw(img)

    draw.text((7, 10), flag[:16], fill=255)
    draw.text((7, 25), flag[16:32], fill=255)
    draw.text((7, 40), flag[32:], fill=255)

    # Convert to numpy array
    img = np.asarray(img, dtype=np.uint8)

    # Invert the image
    if len(sys.argv) > 2 and sys.argv[2] == 'invert':
        img = 255 - img

    # Scale the image to [0,15]
    img = (img - img.min()) / (img.max() - img.min()) * 15

    # Convert to uint8
    img = img.astype(np.uint8)

    # Condense adiacent pixels in rows into single 8-bit values
    bitmap = []
    for row in img:
        for i in range(0, len(row), 2):
            bitmap.append(row[i] << 4 | row[i + 1])

    bitmap = np.array(bitmap, dtype=np.uint8).tobytes()

    NSTEPS = 10

    def ROT(x, n):
        return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

    def ALZETTE(x, y, c):
        x = (x + ROT(y, 31)) & 0xFFFFFFFF
        y = (y ^ ROT(x, 24)) & 0xFFFFFFFF
        x ^= c
        x = (x + ROT(y, 17)) & 0xFFFFFFFF
        y ^= ROT(x, 17)
        x ^= c
        x = (x + y) & 0xFFFFFFFF
        y ^= ROT(x, 31)
        x ^= c
        x = (x + ROT(y, 24)) & 0xFFFFFFFF
        y ^= ROT(x, 16)
        x ^= c
        return x, y

    def ADD_KEY(a, b, c, d, x, y, key):
        a = a & 0xFFFFFFFF
        b = b & 0xFFFFFFFF
        c = c & 0xFFFFFFFF
        d = d & 0xFFFFFFFF
        x ^= c
        x ^= key[0 + (a % 2)]
        y ^= key[1 + (a % 2)]
        x ^= d
        return x, y

    RCON = [0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, 0xBB1185EB]

    def craxs10_enc_ref(xword, yword, key):
        for step in range(NSTEPS):
            xword, yword = ADD_KEY(step, 0, 0, step, xword, yword, key)
            xword, yword = ALZETTE(xword, yword, RCON[step % 5])
        xword, yword = ADD_KEY(0, 0, 0, 0, xword, yword, key)
        return xword, yword

    key = [0x22312, 0x5fa32b, 0x5ac810, 0x1337]

    plaintext = list(struct.unpack('<' + 'I' * (len(bitmap) // 4), bitmap))
    iv = [0, 0]
    for i in range(0, len(plaintext), 2):
        plaintext[i] ^= iv[0]
        plaintext[i + 1] ^= iv[1]
        plaintext[i], plaintext[i + 1] = craxs10_enc_ref(plaintext[i], plaintext[i + 1], key)
        iv[0] = plaintext[i]
        iv[1] = plaintext[i + 1]

    enc = struct.pack('<' + 'I' * (len(plaintext)), *plaintext)

    return enc.hex()


def gen_attachment(path: str, flag: str):
    output = make_output(flag)

    with open(path, "w") as f:
        f.write(output)


def main():
    userid = sys.argv[1]
    flag_base = b'openECSC{1_l1k3_th1z_n3w_ins7ructi0n5_%s}'
    flag = gen_custom_flag(flag_base)

    gen_attachment(f'attachments/out.enc/{userid}', flag.decode())
    print(flag.strip(b'\x00').decode())

if __name__ == '__main__':
    main()
