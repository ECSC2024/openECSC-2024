def ror(x, y):
    return (x >> y | x << (16 - y)) & 0xFFFF


def rol(x, y):
    return (x << y | x >> (16 - y)) & 0xFFFF


# speck round
def speck_round(x, y, k):
    x = ror(x, 8)
    x = (x + y) & 0xFFFF
    x = x ^ k
    y = rol(y, 3)
    y = y ^ x
    return x, y


def speck_inverse_round(x, y, k):
    y = y ^ x
    y = ror(y, 3)
    x = x ^ k
    x = (x - y) & 0xFFFF
    x = rol(x, 8)
    return x, y


def encrypt(k1, k2, x, y):
    for i in range(22):
        x, y = speck_round(x, y, k2)
        k1, k2 = speck_round(k1, k2, i)
    return k1, k2, x, y


def decrypt(k1, k2, x, y):
    round_keys = []
    for i in range(22):
        round_keys.append((k1, k2))
        k1, k2 = speck_round(k1, k2, i)
    
    for i in range(21, -1, -1):
        x, y = speck_inverse_round(x, y, round_keys[i][1])

    return x, y

with open('output.txt', 'r') as f:
    out = f.read()

import re

regex = r"Tree/Leaf/tag ([01])\)"
binary = re.findall(regex, out)
binary = ''.join(binary)

# split in 32 bits
binary = [binary[i:i+32] for i in range(0, len(binary), 32)]
# split each 32 in (16,16) tuples
cts = [(int(b[:16], 2), int(b[16:], 2)) for b in binary]

_k = [
    (43418 , 42714 , 28528 , 38463),
    (11853 , 55605 , 25966 , 48943),
    (7000 , 50060 , 17731 , 46359),
    (58534 , 56580 , 21315 , 28647),
    (3852 , 46811 , 31572 , 59416),
    (7280 , 61910 , 18505 , 20205),
    (31476 , 58745 , 21343 , 47889),
    (61439 , 52037 , 18771 , 429),
    (63343 , 22807 , 24385 , 50471),
    (17925 , 49889 , 24390 , 22568),
    (31528 , 13244 , 16715 , 55712),
    (3604 , 20559 , 17759 , 36772),
    (50138 , 35287 , 17996 , 31213),
    (27415 , 16291 , 16711 , 25633),
    (34707 , 59676 , 24404 , 19203),
    (22998 , 42645 , 18505 , 22976),
    (48192 , 12640 , 21343 , 40651),
    (62478 , 35294 , 18771 , 37626),
    (35745 , 59992 , 24385 , 58772),
    (8086 , 10425 , 24390 , 5505),
    (3361 , 64020 , 16715 , 45026),
    (43426 , 30243 , 17759 , 51598),
    (15093 , 871 , 17996 , 53717),
    (34351 , 15088 , 16711 , 17173),
    (40944 , 55415 , 24404 , 41794),
    (22105 , 47786 , 18505 , 37942),
    (45515 , 38617 , 21343 , 33708),
    (62634 , 60377 , 18771 , 44550),
    (44682 , 27639 , 24385 , 7312),
    (49040 , 33309 , 24390 , 46674),
    (59259 , 21129 , 16715 , 54674),
    (16724 , 43999 , 17789 , 21850)
]
key = [(k1, k2) for k1, k2, _, _ in _k]
print(key)

redacted_pt = [(pt1, pt2) for _, _, pt1, pt2 in _k]
redacted_flag = b''.join([int.to_bytes(x, length=2, byteorder='big') for x, _ in redacted_pt]).decode()
assert redacted_flag == 'openECSC{THIS_IS_A_FAKE_FLAG_THIS_IS_A_FAKE_FLAG_THIS_IS_A_FAKE}'
print(redacted_flag)

pts = [decrypt(k1, k2, x, y) for (k1,k2),(x,y) in zip(key,cts)]
print(pts)

flag = b''.join([int.to_bytes(x, length=2, byteorder='big') for x, _ in pts]).decode()

# assert flag == 'openECSC{oH_my_p4ra7l3l_w0rlds_aR3_f0ld1ng_and_b3nd1ng_37069287}'
print(flag)


