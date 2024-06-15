import gmpy2
import json

sbox = [x+int(gmpy2.next_prime(x)) for x in range(256)]
flag = json.loads(open("attachments/next_output.txt/1").read())

res = ''

for el in flag:
    res += chr(sbox.index(el))

print(res)