with open("output.txt") as f:
    key = eval(f.readline().split(" = ")[1])
    enc_flag = eval(f.readline().split(" = ")[1])

n = len(enc_flag)

def spin(w, n):
    n = n % len(w)
    return w[-n:] + w[:-n]

def decrypt(ct, key):
    pt = ct
    for i in range(n-1, 0, -1):
        k = key[pt[i-1]]
        pt = pt[:i] + spin(pt[i:], -k)
    return pt

flag = decrypt(enc_flag, key)
print(flag)