#!/usr/bin/python
from z3 import *

# Data must be in 32 bit chunks, because I'm lazy.
def z3crc32(data, crc = 0):
    crc ^= 0xFFFFFFFF
    for c in data:
        for block in range(24, -1, -8):
            crc ^= LShR(c, block) & 0xFF
            for i in range(8):
                crc = If(crc & 1 == BitVecVal(1, 32), LShR(crc, 1) ^ 0xedb88320, LShR(crc, 1))
    return crc ^ 0xFFFFFFFF

s = Solver()
data = [BitVec('data'+str(i),32) for i in range(128//4)] # The "string", actually 5 32-bit buffers

# Returns a z3 expression that is true iff the input BitVec32 as a 4-byte string is all ascii.
def isAsciiUppercase(bv):
    # Note the use of z3.And here. Using python's `and` would be incorrect!
    return And(0 <= (LShR(bv,  0) & 0xff), (LShR(bv,  0) & 0xff) < 25,
               0 <= (LShR(bv,  8) & 0xff), (LShR(bv,  8) & 0xff) < 25,
               0 <= (LShR(bv, 16) & 0xff), (LShR(bv, 16) & 0xff) < 25,
               0 <= (LShR(bv, 24) & 0xff), (LShR(bv, 24) & 0xff) < 25)

for d in data[:5]:
    s.add(isAsciiUppercase(d))

for d in data[5:]:
    s.add(d==0x0)

crc = z3crc32(data)

# Assert that the crc is any of the below
# Note the use of z3.Or here. Using python's `or` would be incorrect!
s.add(crc == 0xbadc0ff3)

print(s.check())
m = s.model()

# Interpret a python int as 4 bytes of string
def intToText(x):
    return hex(x)[2:].strip('L').ljust(8,'0').decode('hex')

s = b''
for d in data:
    s += m.eval(d).as_long().to_bytes(4, 'big')

# Verify that the found string as desired, and that the CRC is in fact one of the desired ones.
import zlib
print(s.ljust(128,b"\x00"), hex(zlib.crc32(s.ljust(128,b"\x00"))))
code=""
for i, c in enumerate(s.rstrip(b"\x00")):
    code+="0"+chr(ord('A')+i)+chr(ord('A')+c)

print(code)
