from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import sha256

output_file = open("public.txt", "r")

n = 10
N1 = 20
N2 = 20
L1 = 5
L2 = 8
L = 15

Jn = groups.misc.Cactus(n)
s = Jn.group_generators()

a = eval(output_file.readline().split(" = ")[1])
b = eval(output_file.readline().split(" = ")[1])
b1 = eval(output_file.readline().split(" = ")[1])
a1 = eval(output_file.readline().split(" = ")[1])

def my_len(elem):
    return len(str(elem).split("*"))

b1 = b1[0]

my_sa = []

for _ in range(L):
    min_len = my_len(b1)
    cur_best = None
    for i in range(N1):
        hope = a[i]*b1*a[i]**-1
        if my_len(hope) < min_len:
            cur_best = i
            min_len = my_len(hope)
    my_sa.append(cur_best)
    b1 = a[cur_best]*b1*a[cur_best]**-1

sa = my_sa[::-1]
A = prod(a[i] for i in sa)

shared_a = A**-1 * prod(a1[i] for i in sa)

ciphertext = output_file.readline()

key = sha256(str(shared_a).encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = unpad(cipher.decrypt(bytes.fromhex(ciphertext)), AES.block_size).decode()
print(flag)