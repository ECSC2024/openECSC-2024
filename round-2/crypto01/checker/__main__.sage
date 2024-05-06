#!/usr/bin/env sage

from Crypto.Util.number import bytes_to_long, long_to_bytes
import os
from pwn import remote
from itertools import combinations
import logging

logging.disable()

HOST = os.environ.get("HOST", "invention.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38011))

p = 0xffffffffffffffffffffffffffffffff7fffffff
N = p.bit_length()//8
F = GF(p)
a = F(0xffffffffffffffffffffffffffffffff7ffffffc)
b = F(0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45)
E = EllipticCurve(F, (a, b))
G = E(0x4a96b5688ef573284664698968c38bb913cbfc82, 0x23a628553168947d59dcc912042351377ac5fb32)
n = 0x0100000000000000000001f4c8f927aed3ca752257
E.set_order(n)

d = F(1)
while d.is_square():
    d += 1

nt = 0xfffffffffffffffffffe0b3706d8512b358adda9
ET = E.quadratic_twist(d)
ET.set_order(nt)
GT = ET.gens()[0]

def hash_block(M, Ci, CTi):
    try:
        Pm = E.lift_x(M)
        Ci += Pm
    except:
        Pm =  ET.lift_x(M*d*4)
        CTi += Pm
    return Ci, CTi

def elliptic_hash(Pu, PTu, m):
    assert len(m) >= 2*N

    if len(m) % N != 0:
        pad_length = N - (len(m) % N)
        m += b"\x80"
        m += b"\x00"*(pad_length-1)

    m_blocks = [ZZ(bytes_to_long(m[i:i+N])) for i in range(0, len(m), N)]

    k0 = m_blocks[0]
    k1 = m_blocks[1]


    Ci = k0*Pu
    CTi = k1*PTu

    for i in range(2, len(m_blocks)):
        Ci, CTi = hash_block(m_blocks[i], Ci, CTi)

    return Ci, CTi

# precomputed p160 points
hs = [1217026089109958965601498719303868517806436843678, 759448250872938908677880028896924254805920193388, 569173398545399153150935989280567361233052263967, 1199332692307752283550912627888456483713217610524, 1079027481086532546300937867602186580109338741185, 1069059598553897685855916305006912095069249705224, 288315851873985034955567433589056437908480638959, 12045287124509758747086019002237774348075329126, 864117480199393342910610778363331267214279559672, 776470851910979264466357554533884486586230065570, 125353821621861442391960712727526298446557293195, 678687985152159619473210367825117510967511359391, 708868983378893084885762006582760347810790708333, 1456821013185649722962670579831626142255403649699, 1087880777291130166057466480619109904235474963817, 1157573364993699351931989005203835939365433852923, 114689096430069459590931860024621684190362406651, 1146550305237141315493982764352276847601544061131, 365275067682288802773719966114934668167985864518, 1084568201469664034342141842730256563547003724763, 747398271589005252059207252040131711215995514190, 1027179285114999715411727668473724213549647450584, 601844635799634280083241679791178199170445676818]

xs = {h : long_to_bytes(int((h*G).xy()[0])) for h in hs}

def find_comb(hs, target):
    n_qs = len(hs)
    m = [[1 if i == j else 0 for i in range(n_qs + 2)] for j in range(n_qs + 2)]
    for i in range(n_qs):
        m[i][-2] = hs[i]
    m[n_qs][-2] = target
    m[n_qs][-1] = 2**100
    m[-1][-2] = G.order()
    m[-1][-1] = 0

    M = matrix(ZZ, m)
    M.rescale_col(n_qs, 2**500)

    M1 = M.LLL()
    for row in M1:
        if abs(row[-1]) == 2**100 and row[-2] == 0:
            if (all(x <= 0 for x in row[:-2]) and row[-1] > 0) or (all(x >= 0 for x in row[:-2]) and row[-1] < 0):
                return row[:-2]
    return None

if __name__ == "__main__":
    with remote(HOST, PORT) as chall:
        k1 = int(chall.recvline().decode().split(" = ")[1])
        k2 = int(chall.recvline().decode().split(" = ")[1])

        Pu = k1*G
        PTu = k1*GT

        username = "ciao"
        pwd = b"a"*N + b"".join(xs.values())

        chall.recvline()
        chall.recvline()

        chall.sendlineafter(b": ", username.encode())
        token = chall.recvline().decode().strip().split()[-1]

        chall.sendlineafter(b": ", (token.encode() + pwd).hex().encode())
        chall.recvline()
        admin_pwd = bytes.fromhex(chall.recvline().decode().split("'")[-2])
        admin_pwd_blocks = [admin_pwd[i:i+N] for i in range(0, len(admin_pwd), N)]

        C1, CT1 = elliptic_hash(Pu, PTu, admin_pwd)

        prefix = token.encode()

        payload_blocks = [prefix, admin_pwd_blocks[1]]

        target = ((bytes_to_long(admin_pwd_blocks[0]) - bytes_to_long(payload_blocks[0]))*k1) % G.order()

        for used_hs in combinations(hs, r=12):
            comb = find_comb(used_hs, target)
            if comb != None:
                break

        for c, h in zip(comb, used_hs):
            payload_blocks += [xs[h] for _ in range(abs(c))]

        payload_blocks += admin_pwd_blocks[2:]

        payload = b"".join(payload_blocks)

        chall.sendlineafter(b": ", username.encode())
        chall.sendlineafter(b": ", payload.hex().encode())
        flag = chall.recvline().decode().strip().split()[-1]

        print(flag)


