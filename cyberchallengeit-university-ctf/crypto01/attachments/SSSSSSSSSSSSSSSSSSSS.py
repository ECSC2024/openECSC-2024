#!/usr/bin/env python3
from os import environ

flag = environ.get('FLAG', 'CCIT{REDACTED}').encode()
assert flag.startswith(b'CCIT{')
assert flag.endswith(b'}')

S = [120, 41, 183, 252, 96, 74, 43, 182, 251, 56, 248, 121, 13, 84, 245, 54, 178, 235, 207, 254, 45, 58, 2, 89, 200, 101, 133, 249, 119, 142, 239, 211, 50, 29, 77, 72, 107, 230, 104, 229, 241, 11, 57, 215, 155, 234, 247, 113, 122, 130, 22, 12, 212, 88, 49, 174, 176, 206, 243, 100, 255, 106, 87, 115, 195, 188, 194, 123, 161, 62, 48, 216, 98, 173, 137, 78, 213, 36, 240, 47, 65, 236, 85, 18, 166, 170, 28, 204, 148, 125, 232, 189, 0, 196, 64, 242, 16, 80, 150, 169, 167, 165, 220, 168, 7, 23, 21, 141, 30, 93, 26, 68, 35, 70, 9, 218, 69, 158, 105, 180, 110, 60, 83, 186, 112, 172, 44, 27, 205, 76, 198, 99, 225, 222, 184, 154, 102, 193, 237, 118, 139, 157, 61, 92, 146, 253, 246, 1, 4, 24, 79, 10, 228, 97, 187, 33, 227, 15, 191, 59, 192, 40, 156, 201, 250, 67, 210, 114, 19, 94, 73, 214, 163, 164, 90, 226, 20, 203, 231, 82, 197, 134, 221, 199, 219, 42, 103, 190, 147, 144, 17, 108, 52, 31, 3, 6, 209, 66, 51, 208, 217, 153, 86, 14, 171, 224, 37, 127, 136, 151, 140, 55, 131, 95, 38, 5, 75, 185, 202, 149, 145, 39, 160, 25, 244, 46, 126, 138, 181, 177, 53, 117, 116, 128, 238, 32, 135, 111, 109, 143, 34, 124, 223, 233, 8, 71, 152, 63, 175, 159, 129, 179, 91, 132, 81, 162]
ss = 105

s = []
for sss in flag:
    ssss = ss
    while sss:
        ssss = S[ssss]
        sss -= 1
    s.append(ssss)

print(bytes(s).hex())


