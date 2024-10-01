# openECSC 2024 - Final Round

## [crypto] Encrygnature (5 solves)

Swappity swoppity, can you break this cryptography?

note: it is recommended to use sagemath-10.4 to run the challenge locally, due to performance reasons.

This is a remote challenge, you can connect with:

`nc encrygnature.challs.open.ecsc2024.it 47005`

Author: Francesco Felet <@PhiQuadro>

## Overview

This challenge implements the [Li et al. ID-based signcryption scheme](https://www.sciencedirect.com/science/article/pii/S0895717711003840), with slight custom modifications to make it work with type-3 pairing-friendly elliptic curves. In this case, a [Barreto-Naehrig](https://eprint.iacr.org/2005/133.pdf) curve over a prime field of 128 bits is randomly generated for each connection. Even if these custom curves do not satisfy the usual requirements in terms of dlog security (on the curve and on $\mathbb{F}_{p^{12}}$), they still provide 64 and 82 bits of security respectively, which are hard to break in the 24h available during the competition.

tl;dr: a signcryption scheme tries to merge asymmetric signature and encryption functionalities. ID-based means that a public key for a user is just their ID (a binary string), which is supposedly a more convenient alternative to a traditional PKI.

Even if the challenge is relatively code-heavy, we can abstract fairly quickly what is happening:

    - a Private Key Generator generates the scheme parameters and broadcasts the public ones
    - when users are created, they invoke the PKG to get their private key
    - a user can then encrygn (signcrypt) a message to another user and "submit" the ciphertext and relative metadata to the system
    - upon receiving a ciphertext, the system unencrygns (unsigncrypts) it with the receiving end's private key, logging the corresponding plaintext if a check is passed
    - two messages between default users are sent before we can interact with the challenge, one of which includes the flag (but the corresponding plaintext is redacted)
    - we can register new users, see the logs and deliver ciphertexts to the system
    - there is an anti-replay mechanism

## Solution

In this scheme, a ciphertext is a tuple of six elements $(s_{1}, s_{2}, s_{3}, s_{4}, s_{5}, s_{6})$.

If we look closely at what's happening in the `unencrygn` method, we can see that $s_{3}$ is not taken into account at all. Moreover, a change in $s_{3}$ implies a change in the message obtained after decryption. Ciphertexts are malleable! If we can control that resulting change in the plaintext, we obtain a nice and old blinding attack.

Indeed, if we choose a random $\beta$ from the appropriate group and set $s_{3}^{\prime} = s_{3} + \beta$, the corresponding plaintext ends up being (using bilinearity):

```math

\begin{aligned}

m^{\prime} &= s_{1} \cdot \frac{e(s_{3} + \beta, sk_{bob}^{1})}{e(sk_{bob}^{0}, s_{2})} \\
           &= s_{1} \cdot \frac{e(s_{3}, sk_{bob}^{1})}{e(sk_{bob}^{0}, s_{2})} \cdot e(\beta, sk_{bob}^{1}) \\
           &= m \cdot e(\beta, sk_{bob}^{1})

\end{aligned}

```

$sk_{bob}^{1}$ is given for free as $s_{4}$ in bob's response.

Unfortunately, a typo at line 307 of the source code (`c_ret` should have been the decoded `c_`) allowed for an unintended solution, which consists in delivering alice's ciphertext back to the system without the first block and obtaining the plaintext for free. *sigh*.

## Exploit

```py
#!/usr/bin/env sage
from random import SystemRandom
from tqdm import tqdm
from functools import partial
from hashlib import sha256
from json import loads, dumps
from Crypto.Util.Padding import pad, unpad
from pwn import remote, process
from tqdm import tqdm

BITS = 128
BYTES = ceil(BITS/8)
LOCAL = False

if LOCAL:
    host, port = 'localhost', '47005'
else:
    host, port = 'encrygnature.challs.open.ecsc2024.it', '47005'

def intify(x):
    return list(map(int, x))

def strify(x):
    return list(map(str, x))

class BN:
    def __init__(self, params):
        rng = SystemRandom()
        randrange = lambda *args: rng.randrange(*args)

        self.p = params['p']
        self.Fp = GF(self.p)
        
        self.k   = 12
        self.b   = params['b']
        EFp = EllipticCurve(self.Fp, [0, self.b])
        self.EFp = EFp
        self.n = self.EFp.order()
        self.t = self.EFp.trace_of_frobenius()

        G1 = self.EFp.lift_x(1)

        Fp2.<a> = GF(self.p^2)
        self.Fp2 = Fp2

        self.eps = Fp2(params['eps'])
        
        self.EFp2 = EllipticCurve(self.Fp2,  [0, self.b/self.eps])        
        EFp2_ord = self.EFp2.order()
        cof = EFp2_ord//self.n

        self.G2 = self.EFp2(list(map(self.Fp2, params['G2'])))

        Fp2u.<u> = self.Fp2[]
        Fp12.<z> = (u^6 - self.eps).root_field()

        self.Fp2u   = Fp2u
        self.Fp12   = Fp12
        self.z      = z
        self.EFp12  = EllipticCurve(self.Fp12, [0, self.b])
        self.G1     = G1

        self.O_EFp  = self.EFp([0, 1, 0])
        self.O_EFp2 = self.EFp2([0, 1, 0])

        self.json = {
            'b'  : int(self.b),
            'p'  : int(self.p),
            'eps': str(self.eps),
            'G1' : intify(self.G1.xy()),
            'G2' : strify(self.G2.xy())
        }

    def phi(self, P):
        assert P in self.EFp2 and P != self.O_EFp2 and self.n*P == self.O_EFp2, f'Point {P} not in <G2>'
        Px, Py = P.xy()
        return self.EFp12(self.z^2 * Px, self.z^3 * Py)
    
    def e(self, P, Q):
        assert P in self.EFp  and P != self.O_EFp, f'Point {P} not in <G1>'
        assert Q in self.EFp2 and Q != self.O_EFp2 and self.n*Q == self.O_EFp2, f'Point {Q} not in <G2>'
        return self.EFp12(P).ate_pairing(self.phi(Q), self.n, self.k, self.t, self.p)

class User:
    def __init__(self, all_params, sk, uid):
        # export what's available from the PKG
        self.curve = BN(all_params['curve'])
        self.r     = SystemRandom()
        self.p     = self.curve.n
        
        # decode pkg params
        # G1 elements
        self.g1, self.u_, self.m_, =  [self.curve.EFp(all_params[k])              for k in ['g1', 'u_', 'm_']]
        self.U,  self.M            = [[self.curve.EFp(v)  for v in all_params[k]] for k in ['U',  'M']]
        # G2 elements
        self.g, self.g2, self.h    =  [self.curve.EFp2(all_params[k])             for k in ['g', 'g2', 'h']]

        self.uid = intify(f'{int(uid, 16):0{BITS}b}')
        
        self.sk  = (self.curve.EFp(sk[0]), self.curve.EFp2(sk[1]))

    def rng(self):
        return self.r.randrange(self.p)
    
    def H(self, x):
        return int.from_bytes(sha256(x).digest()[:BYTES], 'big') % self.p
    
    def H1(self, *args):
        return self.H(b'||'.join(list(map(lambda x: str(x).encode(), args))) + b'||\x01')
    
    def H2(self, P):
        return self.H(str(P).encode() + b'||\x02')

    def encrygn(self, m, bob):
        m = pad(m, BYTES-1)
        m_blocks = [int.from_bytes(m[i:i+BYTES-1], 'big') for i in range(0, len(m), BYTES-1)]
        
        myid  = sum([self.u_] + [self.U[i] for i in range(BITS) if self.uid[i]], self.curve.O_EFp)
        bobid = sum([self.u_] + [self.U[i] for i in range(BITS) if  bob.uid[i]],  bob.curve.O_EFp)
        
        ciphertext = []
        for m in m_blocks:
            r, s = [self.rng() for _ in range(2)]

            s1 = m * self.curve.e(self.g1, self.g2)^r
            s2 = r * self.g
            s3 = r * bobid
            s4 = self.sk[1]
            t  = self.H1(s1, s2, s4, myid, bobid)
            mh = self.H2(t * self.g + s * self.h)
            mh = intify(f'{int(mh):0{BITS}b}')
            mhid = sum([self.m_] + [self.M[i] for i in range(BITS) if mh[i]], self.curve.O_EFp)
            s5 = self.sk[0] + r * mhid
            s6 = s
            
            s3, s5 = list(map(intify, [s3.xy(), s5.xy()]))
            s2, s4 = list(map(strify, [s2.xy(), s4.xy()]))
            ciphertext.append((str(s1), s2, s3, s4, s5, int(s6)))

        return ciphertext

    def unencrygn(self, c, alice):
        myid    = sum([self.u_] + [self.U[i] for i in range(BITS) if  self.uid[i]],  self.curve.O_EFp)
        aliceid = sum([self.u_] + [self.U[i] for i in range(BITS) if alice.uid[i]], alice.curve.O_EFp)

        plaintext = []
        for c_ in c:
            s1, s2, s3, s4, s5, s6 = c_

            t  = self.H1(s1, s2, s4, aliceid, myid)
            mh = self.H2(t * self.g + s6 * self.h)
            mh = intify(f'{int(mh):0{BITS}b}')
            mhid = sum([self.m_] + [self.M[i] for i in range(BITS) if mh[i]], self.curve.O_EFp)
            lhs = self.curve.e(s5,      self.g)
            rhs = self.curve.e(self.g1, self.g2) * \
                  self.curve.e(aliceid, s4)      * \
                  self.curve.e(mhid,    s2)
            if lhs != rhs:
                return False, []
            
            m = s1 * self.curve.e(s3, self.sk[1]) / self.curve.e(self.sk[0], s2)
            plaintext.append(m)

        return True, plaintext

def decode_ciphertext(c, curve):
    c_ret = []
    for c_ in c:
        s1, s2, s3, s4, s5, s6 = c_
        s1     = curve.Fp12(s1)
        s3, s5 = list(map(curve.EFp, [s3, s5]))
        s2, s4 = list(map(curve.EFp2,[s2, s4]))
        s6 = int(s6)
        c_ret.append([s1, s2, s3, s4, s5, s6])
    return c_ret

def get_uid(uname):
    return sha256(uname).digest()[:BYTES].hex()

def register(uname):
    chall.sendline(b'1')
    chall.sendlineafter(b'username: ', uname)
    chall.recvline()
    sk0 = loads(chall.recvline(False).decode())
    sk1 = loads(chall.recvline(False).decode())
    return sk0, sk1

def conversation_logs():
    chall.recvuntil(b'quit\n\n> ')
    chall.sendline(b'2')
    line = chall.recvline(False).decode()
    return loads(line)['logs']

def deliver_message(msg):
    chall.recvuntil(b'quit\n\n> ')
    chall.sendline(b'3')
    chall.sendline(dumps(msg).encode())

def attack(block):
    s1, s2, s3, s4, s5, s6 = block
    s3 = curve.EFp(s3)
    beta = myuser.rng() * curve.G1
    s3_ = intify((s3 + beta).xy())
    
    msg = {'sender': 'alice', 'receiver': 'bob', 'ciphertext': [(s1, s2, s3_, s4, s5, s6)]}
    deliver_message(msg)

    ptxt1 = conversation_logs()[-1]['plaintext'].strip()[1:-1]
    m_ = curve.Fp12(ptxt1) / curve.e(beta, sk_bob_1)
    return int(m_).to_bytes(BYTES-1, 'big')

with remote(host, port) as chall:
    chall.recvline()
    all_params = loads(chall.recvline(False).decode())
    print(f'[+] received params')

    curve = BN(all_params['curve'])

    sk = register(b'myuser')
    myuser = User(all_params, sk, get_uid(b'myuser'))
    print(f'[+] registered user')

    logs = conversation_logs()
    __ctxt = logs[0]['ciphertext']
    sk_bob_1 = curve.EFp2(logs[1]['ciphertext'][0][3])
    print(f'[+] received logs, attacking..')

    ptxt = b''
    for c in tqdm(__ctxt):
        ptxt += attack(c)

    print(f'{ptxt = }')
```