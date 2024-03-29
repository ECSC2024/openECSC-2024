from collections import defaultdict
import subprocess
import random
from tqdm import tqdm
from pqdm.processes import pqdm
import itertools

"""
start of data obtained reversing the binary
"""

# alphabet
alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# first occurrence of every letter in the alphabet
check_array1 = [5, 7, 15, 3, -1, 21, 24, 126, 73, 56, 2, 1, 10, 4, 70, 42, 64, 0, 17, 66, 22, 59, 58, 45, 101, 301]

# all occurrences of pairs of equal letters (es. "AA" appears in positions 5, 12, 19, ...)
check_array2 = [[5, 12, 19, 26, 33, 40, 47, 54, 61, 68, 75, 82, 89, 96, 97, 103, 110, 117, 124, 131, 138, 145, 152, 159, 166, 173, 180, 187, 194, 201, 208, 215, 222, 229, 236, 243, 250, 251, 257, 264, 271, 278, 285, 292, 299, 306, 313, 320, 327, 334, 341, 348, 355, 362, 369, 376, 383, 390, 397, 404, 411, 418, 425, 426, 432, 439, 446, 453, 460, 467, 474, 481, 488, 495, 496, 502, 509, 516, 517, 523, 530, 537, 544, 551, 558, 565, 572, 573, 579, 586, 593, 600, 607, 614, 621, 628, 635, 642, 649, 656, 663, 670, 677, 684, 691, 692, 698, 705, 712, 719, 720, 726, 733, 740, 747, 754, 761, 768, 775, 782, 789, 796, 803, 810, 817, 824, 831, 838, 845], [], [], [], [], [], [], [], [], [], [], [], [28, 77, 210, 336, 735, 805], [8, 225, 421, 617, 659, 778], [], [], [], [], [], [], [], [], [], [], [], []]

# all occurrences of 3 copies of the same letter
check_array3 = [[96, 250, 425, 495, 516, 572, 691, 719], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], [], []]

# checked substrings
check_array5 = [
        "HJDQMAALCRSMAAATWYKAAKQUTKAARHROKAAYHWLMAAPCMXMAAGVQPMAARLKDNAAZHXQNAAPZDTMAARLKDNAAGVQPMAAOAMINAAMMCKLAARLKDNAARLKDNAAOAMINAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAAL",
        "HXQNAALCRSMAARHROKAARLKDNAABNNMKAAJAWVMAAKQUTKAARVKXMAAYHWLMAAPZDTMAABNNMKAAFUBGNAARVKXMAAJAWVMAARVKXMAAATWYKAAGAVRMAARHROKAAPZDTMAAATWYKAAYHWLMAAMMCKLAAGAVRMAARVKXMAARLKDNAARVK",
        "INAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSMAARHROKAARLKDNAABNNMKAAJAWVMAAKQUTKAARVKXMAAYHWLMAAPZDTM",
        "LCRSMAAATWYKAAKQUTKAARHROKAAYHWLMAAPCMXMAAGVQPMAARLKDNAAZHXQNAAPZDTMAARLKDNAAGVQPMAAOAMINAAMMCKLAARLKDNAARLKDNAAOAMINAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSMAARHROKAARLKDNAABNNMKAAJAWVMAAKQUTKAARVKXMAAYHWLMAAPZDTMAABNNMKAAFUBGNAARVKXMAAJAWVMAARVKXMAAATWYKAAGAVRMAARHROKAAPZDTMAAATWYKAAYHWLMAAMMCKLAAGAVRMAARVKXMAARLKDNAARVKXMAAHJDQMAABNNMKAAZHXQNAAOAMINAARHROKAAMMCKLAAYHWLMAAOAMINAARLKDNAAG",
        "MAABNNMKAAGAVRMAAHJDQMAALCRSMAAATWYKAAKQUTKAARHROKAAYHWLMAAPCMXMAAGVQPMAARLKDNAAZHXQNAAPZDTMAARLKDNAAGVQPMAAOAMINAAMMCKLAARLKDNAARLKDNAAOAMINAAKQUTKAAGVQPMAAKQUTKAAFUBGNAAPCMXMAAFUBGNAAYHWLMAAGAVRMAABNNMKAAATWYKAARLKDNAALCRSMAAPCMXMAARHROKAAJAWVMAAGAVRMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSMAARHROKAARLKD",
        "MAAJAWVMAARLKDNAAMMCKLAARVKXMAABNNMK",
        "MINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSM",
        "MMCKLAARLKDNAAPCMXMAARLKDNAAJAWVMAAKQUTKAAOAMINAAMMCKLAAOKOANAARVKXMAAATWYKAAOAMINAAKQUTKAAFUBGNAAHJDQMAAOAMINAAJAWVMAAOKOANAALCRSMAAGVQPMAAYHWLMAAHJDQMAARVKXMAALCRSMAAJAWVMAARLKDN",
        "RMAAOAMINAAPCMXMAARVKXMAAATWYKAARVKXMAAFUBGNAAATWYKAAYHWLMAARLKDNAARHROKAARLKDNAAFUBGNAAPCMXMAARLKDNAAATWYKAALCRSMAAZHXQNAALCRSM",
        "SMAAGVQPM"
]

# positions of the previous substrings if we order all the substrings of the preprocessed input in lexicographical order
check_array4 = [150522, 156400, 158842, 197423, 212845, 218209, 237975, 241733, 299651, 310452]

# exact number of distinct substrings of the preprocessed input
n_substrings = 353624

# main function used to preprocess the input
# the input format is ABCDE-FGHIJ-... with total length 725 -> 121 chunks of 5 chars separated by dashes
# preprocessing is done removing dashes and passing every 5-char chunk through this "hash", that return a 7-chars long string
# preprocessed input has length 121*7 = 847
def hash_string(s):
    h = high = 0
    ret = ""

    for i in range(len(s)):
        h = (h << 4) + ord(s[i])
        high = h & 0xF0000000
        h ^= high >> 24
        h &= high ^ 0xFFFFFFFF
    
    for i in range(7):
        ret += alph[h%26]
        h //=26
    
    return ret

"""
end of data obtained reversing the binary
"""

# our guess for the hashed input
hashed_key = "_"*(121*7) # every chunk of the key is mapped to 7 chars

# we sort the substrings that we have by length: the longest one has probably more information, so we start placing it
# we place it by matching on substrings "AAA", that are a lot and give more info than single characters
check_array5_s = sorted(check_array5, key = lambda x: len(x), reverse = True)
tmp = check_array5_s[0]
print([n for n in range(len(tmp)) if tmp.find("AAA", n) == n]) # [5, 180, 250, 271, 327, 446, 474] -> the 271-250 difference can be mapped only to the 516-495 difference in check_array3
hashed_key = hashed_key[:495-250] + tmp + hashed_key[495-250+len(tmp):]

# we place all the info about the positions of single, double and triple letters
hashed_key = bytearray(hashed_key.encode())

for i in range(26):
    if check_array1[i] != -1:
        hashed_key[check_array1[i]] = ord(alph[i])
    for el in check_array2[i]:
        for j in range(2):
            hashed_key[el+j] = ord(alph[i])
    for el in check_array3[i]:
        for j in range(3):
            hashed_key[el+j] = ord(alph[i])

hashed_key = bytes(hashed_key).decode()

# we start now placing the remaining substrings greedily
# we go again from the longest to the shortest
for j,s in enumerate(check_array5_s[1:]):
    count = 0
    pos = []
    for offset in range(121*7 - len(s)):
        for i in range(len(s)):
            if hashed_key[i+offset] != '_' and hashed_key[i+offset] != s[i]:
                break
        else:
            print(f"{j} can fit at offset {offset}")
            count += 1
            pos.append(offset)
    
    if count == 1:
        hashed_key = bytearray(hashed_key.encode())
        for i in range(len(s)):
            hashed_key[pos[0]+i] = ord(s[i])
        hashed_key = bytes(hashed_key).decode()

print(f"Missing: {hashed_key.count('_')} chars")
missing_chars = [n for n in range(len(hashed_key)) if hashed_key.find("_", n) == n]
print(missing_chars)

# list of all the substrings
subs = sorted(list([hashed_key[i:j] for i in range(len(hashed_key)) for j in range(i+1, len(hashed_key)+1)]))

gaps = []
for i,el in enumerate(check_array5):
    gaps.append(check_array4[i]-subs.index(el)-1)

# how many substrings do we miss?
print(gaps)

# upper positions: 11, 14, 16, 18, 23, 25
# -> exactly one < H because of conditions 1, 2, 3
# -> exactly one = K because of condition 4
# -> pos 18 == M because of conditions 5, 6, 7
hashed_key = hashed_key[:18] + "M" + hashed_key[19:]
print(hashed_key)
hashed_key_chunks = [hashed_key[i:i+7] for i in range(0, len(hashed_key), 7)]

gaps = []
for i,el in enumerate(check_array5):
    gaps.append(check_array4[i]-subs.index(el)-1)

possible_hashes_cache = {}

for a in alph:
    for b in alph:
        for c in alph:
            for d in alph:
                for e in alph:
                    h = hash_string(a+b+c+d+e)
                    possible_hashes_cache[h] = a+b+c+d+e


candidates = [[] for _ in range(3)]

for i,chunk in enumerate(hashed_key_chunks[:4]):
    if '_' not in chunk:
        continue
    print(chunk)
    cnt = 0
    for c in possible_hashes_cache:
        for pos in range(7):
            if chunk[pos] != '_' and chunk[pos] != c[pos]:
                break
        else:
            for j,x in enumerate(alph):
                if (x*2 in c and x*2 not in chunk) or (x*3 in c and x*3 not in chunk):
                    break
                if (x in c and check_array1[j] == -1) or (x in c and check_array1[j] > 7*i+c.index(x)):
                    break
            else:
                cnt += 1
                candidates[i-1].append(c)
    print(f"candidates {cnt}")

candidates_upper = []

for a in candidates[0]:
    for b in candidates[1]:
        for c in candidates[2]:
            if 'K' in a+b+c and sum([x < "H" for x in [a[4], b[0], b[2], c[2], c[4]]]) == 1:
                tmp_hashed_key = hashed_key_chunks[0]+a+b+c+''.join(hashed_key_chunks[4:])
                assert len(tmp_hashed_key) == 847
                subs = sorted(list([tmp_hashed_key[i:j] for i in range(len(tmp_hashed_key)) for j in range(i+1, len(tmp_hashed_key)+1)]))

                gaps = []
                for i,el in enumerate(check_array5):
                    gaps.append(check_array4[i]-subs.index(el)-1)

                if all(100>x>0 for x in gaps):
                    print("adding")
                    candidates_upper.append((a,b,c))

print(candidates_upper)

# candidates_upper = [('BNNMKAA', 'ACLSMAA', 'FUSGNAA'), ('BNNMKAA', 'BCLSMAA', 'FUSGNAA'), ('BNNMKAA', 'DCLSMAA', 'FUSGNAA'), ('BNNMKAA', 'ACRSMAA', 'FULGNAA'), ('BNNMKAA', 'BCRSMAA', 'FULGNAA'), ('BNNMKAA', 'DCRSMAA', 'FULGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUAGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUBGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUCGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUDGNAA'), ('BNNMKAA', 'LCRSMAA', 'FUFGNAA')]

upper_gaps = []
for (a,b,c) in candidates_upper:
    tmp_hashed_key = hashed_key[:7] + a+b+c + hashed_key[28:]
    subs = sorted(list([tmp_hashed_key[i:j] for i in range(len(tmp_hashed_key)) for j in range(i+1, len(tmp_hashed_key)+1)]))
    gaps = []
    for i,el in enumerate(check_array5):
        gaps.append(check_array4[i]-subs.index(el)-1)
    print((a,b,c), gaps)
    upper_gaps.append(tuple(gaps))

candidates = [[] for _ in range(2)]
hashed_key_chunks = [hashed_key[i:i+7] for i in range(0, len(hashed_key), 7)]

for i,chunk in enumerate(hashed_key_chunks[-2:]):
    if '_' not in chunk:
        continue
    print(chunk)
    cnt = 0
    for c in possible_hashes_cache:
        for pos in range(7):
            if chunk[pos] != '_' and chunk[pos] != c[pos]:
                break
            if i == 1 and pos == 0:
                if c[pos] != 'R':
                    break
            if i == 0:
                if sum([x <= 'H' for x in c]) > 4:
                    break
                if sum([x >= 'S' for x in c]) > 1:
                    break
                if pos == 0 and c[pos] >= 'S':
                    break
                if pos == 4 and c[pos] != 'M':
                    break
        else:
            for j,x in enumerate(alph):
                if (x*2 in c and x*2 not in chunk) or (x*3 in c and x*3 not in chunk):
                    break
            else:
                cnt += 1
                candidates[i].append(c)
    print(f"candidates {cnt}")

def last_step(upper_gap):
    ret = []
    for a,b in itertools.product(candidates[0], candidates[1]):
        x = (a+b)[1:]

        v = sorted([x[i:j] for i in range(len(x)) for j in range(i+1, len(x)+1)] + check_array5)

        for i in range(10):
            if v.index(check_array5[i]) != upper_gap[i] + 20 + i:
                break
        else:
            # print("adding", x, upper_gap)
            ret.append((x, upper_gap))

result = pqdm(list(set(upper_gaps)), last_step, n_jobs=len(set(upper_gaps)))
print(result)