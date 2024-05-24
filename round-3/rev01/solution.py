import numpy as np
import struct
import sys

CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWX{}_!"
KEY = 0x1337dead1337beef

with open(sys.argv[1], 'rb') as f:
    out = f.read()

parsed = []

for i in range(0, len(out), 8):
    parsed.append(struct.unpack('<q', out[i:i+8])[0] ^ KEY)

segments = []
for i in range(0, len(parsed), 64*64):
    segments.append(np.array(parsed[i:i+64*64], dtype=np.int64).reshape((64,64)))

codes = {}
codes_num = {}
decoded = {}
for i in range(0, len(segments), 2):
    tx = segments[i]
    carrier = segments[i+1]
    id = i//2
    code = np.zeros(64, dtype=np.int8)
    for j, x in enumerate(carrier[:32]):
        if not all(x == 0):
            code = x
            break

    code = int.from_bytes(np.packbits(code).tobytes(), 'big')
    #print(id)
    codes_num[id] = code
    codes[id] = np.array([-1 if (code >> _)&1 else 1 for _ in range(64)][::-1])
    decoded[id] = tx@codes[id]//64

## COMPUTE MISSING CODE
code34 = 17361641481138401520
codes[34] = np.array([-1 if (code34 >> _)&1 else 1 for _ in range(64)][::-1])

flag = ""
for i in range(64):
    d = segments[i<<1]@codes[34]//64
    print(d)
    flag += CHARS[d[0]&0xff]
print(flag)
