from z3 import Solver, BitVec, And, sat, Or

s = Solver()

# vector of chars
flag = [BitVec(f'flag__{i}', 8) for i in range(30)]

# add contraints
s.add(And([flag[i] == c for i,c in enumerate(b'openECSC{')]))
s.add(flag[29] == ord('}'))
#s.add(And([flag[i] & 0x80 == 0 for i in range(30)]))

s.add((flag[9] * ord('\x11') + -0x7d + flag[10] * -0x39 + flag[14] * -4 + flag[19] * ord('|') + flag[24] * -7 + flag[28] * ord(';')) == 245)
s.add((flag[9] * ord('2') + ord('j') + flag[10] * ord('\x12') + flag[12] * -0x6b + flag[19] * -0x76 + flag[28] * -0x27) == 119)
s.add((flag[12] * -0x51 + -0x30 + flag[18] * -0x80 + flag[22] * ord('g') + flag[24] * ord('\x1f') + flag[27] * ord('$')) == 253)
s.add((flag[9] * -0x40 + -0x4a + flag[12] * ord('A') + flag[14] * -0x10 + flag[16] * -0x66 + flag[19] * -0x4e + flag[20] * -0x6b + flag[21] * -0x54) == 166)
s.add((flag[12] * ord('x') + -0x17 + flag[27] * -0x49) == 161)
s.add((flag[10] * ord('G') + ord('%') + flag[14] * -0x45 + flag[15] * -0x51 + flag[16] * ord('(') + flag[17] * -0x49 + flag[18] * -0x70 + flag[20] * -0x52 + flag[26]) == 74)
s.add((flag[9] * -0x32 + -0x6e + flag[12] * -0xf + flag[17] * -0x17 + flag[20] * -0x19 + flag[24] * -0x40 + flag[25] * -0x44 + flag[28] * -0x74) == 226)
s.add((flag[19] * ord('u') + ord('=') + flag[22] * ord('.') + flag[24] * ord('C') + flag[25] * ord('k')) == 146)
s.add((flag[16] * -4 + ord('\x05') + flag[20] * ord('q') + flag[25] * -0x76) == 20)
s.add((flag[11] * ord('e') + -0xf + flag[16] * -0x40 + flag[18] * ord('\x19')) == 132)
s.add((flag[11] * ord('C') + ord('-') + flag[14] * ord('\x7f') + flag[15] * ord('\x10') + flag[19] * ord('\'') + flag[20] * -5 + flag[25] * ord('\x11') + flag[28] * ord('/')) == 36)
s.add((flag[9] * -0x79 + ord('%') + flag[22] * -0x22) == 143)
s.add((flag[13] * -0x5b + -0x79 + flag[15] * ord('\x04') + flag[26] * -0x67 + flag[28] * -4) == 44)
s.add((flag[11] * -99 + ord('\'') + flag[14] * ord('a') + flag[15] * ord('\r') + flag[19] * ord('\x14') + flag[20] * ord('\"') + flag[22] * ord('\x17') - flag[23] + flag[26] * ord('\v') + flag[27] * ord('X')) == 20)
s.add((flag[12] * -0x5a + ord('\x05') + flag[17] * ord('\n') + flag[21] * -0x75 + flag[25] * ord('8') + flag[27] * -0x23) == 215)
s.add((flag[11] * -0x60 + -0x3e + flag[15] * -0x39) == 4)
s.add((flag[10] * -0xf + -0x21 + flag[26] * ord('S') + flag[28] * -0x46) == 67)
s.add((flag[11] * -0x5d + -0xc + flag[13] * ord('+') + flag[14] * ord('\x19') + flag[16] * -0x26 + flag[17] * -0x3d + flag[19] * ord('Q')) == 57)
s.add((flag[23] * ord('b') + ord('7') + flag[26] * ord('q') + flag[27] * ord('X')) == 71)
s.add((flag[9] * -0xb + ord('@') + flag[10] * -100 + flag[16] * ord('u') + flag[20] * ord('\v') + flag[24] * -0x4f) == 195)

# print all solutions
while s.check() == sat:
    m = s.model()
    sol = [m[x].as_long() for x in flag]
    print(bytes(sol))
    s.add(Or([ x != m[x] for x in flag]))