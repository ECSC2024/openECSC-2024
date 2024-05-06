from Crypto.Util.number import long_to_bytes
from multiprocessing import Pool
from tqdm import trange
from datetime import datetime
import string

p = 0xffffffffffffffffffffffffffffffff7fffffff
N = p.bit_length()//8
F = GF(p)
a = F(0xffffffffffffffffffffffffffffffff7ffffffc)
b = F(0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45)
n = 0x0100000000000000000001f4c8f927aed3ca752257
E = EllipticCurve(F, (a, b))
G = E(0x4a96b5688ef573284664698968c38bb913cbfc82, 0x23a628553168947d59dcc912042351377ac5fb32)
E.set_order(n)

d = F(1)
while d.is_square():
    d += 1

ET = E.quadratic_twist(d)
GT = ET.gens()[0]

alph = [ord(x) for x in string.printable]

def init_pool_processes():
    set_random_seed()

def find_k(G):
    n = G.order()
    k = randrange(0, n-1)
    P = k*G
    ct = 0
    while True:
        ct += 1
        P += G
        xP = long_to_bytes(int(P.xy()[0]))
        if all(b < 128 for b in xP):
            if int(P.xy()[1]) < int((-P).xy()[1]):
                print(f"k = {k + ct}")
            else:
                print(f"k = {n - (k + ct)}")
            k = randrange(0, n-1)
            P = k*G
            ct = 0

print(f"{datetime.now().hour}:{datetime.now().minute}")

n_threads = 1
with Pool(n_threads, initializer=init_pool_processes) as p:
    p.map(find_k, [G for _ in range(n_threads)])
