# TeamItaly Preselection CTF 2024

## [crypto] Procyon (0 solves)

Cryptography is better when done with friends!

`nc procyon.challs.external.open.ecsc2024.it 38313`

Author: Francesco Felet <@PhiQuadro>

## Overview

This challenge is about a thresholdized implementation of Raccoon, a digital signature scheme based on lattice assumptions. It is described in section 2.2 of [this paper](https://eprint.iacr.org/2024/184.pdf).

### Description of the scheme

We aren't really interested in the mathematical details of the construction, but just as a quick TL;DR, we are working with matrices/vectors which entries are in $$R_q = \frac{\mathbb{Z}_q[x]}{\langle x^n + 1 \rangle}$$

which means that we take the polynomials with coefficients in $\mathbb{Z}_q$ and look at the residue classes modulo $x^n + 1$.

Initially a random $k \times l$ matrix $A$ is sampled, along with two *short* (according to some distribution) vectors $(s, e)$ of appropriate dimension, such that $t = A \cdot s + e$.

The verification (public) key is $vk = (A, t)$, the private portion is $(s, e)$.

Then, the server performs Shamir Secret Sharing Scheme on the private component $s$ between all the users, with threshold $T$ (meaning that any $T$-cardinality subset of users can reconstruct the original private key with Lagrange interpolation). To achieve this, the vector $s = (s_0, s_1, ..., s_{l-1})$ is encoded as a polynomial $s_0 + s_1y + s_2y^2 + ... + s_{l-1}y^{l-1} $ in $R_q[y]$, which is then treated as constant term of an otherwise random polynomial $P$ of degree $T-1$ in $R_q[y][z]$. The shares are then computed as a simple evaluation $P(uid)$, where $uid$ is an integer that identifies uniquely an user. The error term of each share is computed as a short random vector sampled independently from the aforementioned distribution.

We can summarize the signing scheme in three main points:

- **commit and reveal**: each user samples new short vectors $(r_i, e'_i)$ and outputs a hash commitment of $w_i = A\cdot r_i + e'_i$. After collecting every commitment, each user reveals their $w_i$ and checks the correctness of all other reveals, aborting in case of a mismatch with the respective hash.

- **partial signature**: each user can now locally compute the challenge $c = H_c(vk, msg, w)$ where $H_c$ is a hash function mapping to a short element of $R_q$ and $w = \sum w_i = A \cdot (\sum r_i) + \sum e'_i$. The response (partial signature) is then computed as $(z_i, y_i) = (c \cdot \lambda_i \cdot s_i + r_i, c\cdot e_i + e'_i)$, where $\lambda_i$ is the lagrange coefficient of user $i$ with respect to the chosen set of $\geq T$ signers.

- **signature aggregation**: the final signature is then computed as $(c, z, y) = (c, \sum z_i, w - A \cdot z + c\cdot t)$.

Signature verification is performed checking that $c == H_c(vk, msg, A\cdot z + y - c\cdot t)$. In the first version of the challenge no other checks were performed, which allowed for trivial forgeries (i.e. choose $w$, compute $c$, adjust $z$ and $y$ as you please to make verification work). In a lattice-based construction it is **fundamental** to check that the vectors provided are sufficiently short to be a solution of the hard underlying problem (in this case we are talking about module learning with error - MLWE). In fact if we observe a legitimate signature:

$$ \begin{aligned}
z &= \sum z_i = c \cdot \sum (\lambda_i \cdot s_i) + \sum r_i &= c \cdot s + \sum r_i \\
y &= w - A \cdot z + c \cdot t = A \cdot (\sum r_i) + \sum e'_i - c \cdot A \cdot s - A\cdot (\sum r_i) + c\cdot A \cdot s + c\cdot e &= c \cdot e + \sum e'_i
\end{aligned}
$$

which are both short! A fixed version of the challenge with appropriate checks during verification was released as a revenge challenge after noticing this oopsie.

The challenge objective is to forge a valid signature for a target message; we are given access to an arbitrary signing oracle (exception made for our target, which is blacklisted).

## Solution

If we try to plug in the response of a user $(z_i, y_i) = (c \cdot \lambda_i \cdot s_i + r_i, c\cdot e_i + e'_i)$ into the verification equation, we can see that it can be interpreted as a valid Raccoon signature under a peculiar partial public key:

$$ \begin{aligned}
w_i               &= A\cdot z_i + y_i - c \cdot t_i \\
A\cdot r_i + e'_i &= c \cdot \lambda_i \cdot A \cdot s_i + A \cdot r_i + c \cdot e_i + e'_i - c \cdot t_i \\
c \cdot t_i       &= c \cdot \lambda_i \cdot A \cdot s_i + c \cdot e_i \\
            t_i   &= \lambda_i \cdot A \cdot s_i + e_i
\end{aligned}
$$

In particular, we can observe that we can recover $t_i$ using only public information, and that $e_i$ is constant. Therefore we can just perform two queries changing the set of signers (and $\lambda_i$ with it) and solve a linear system in $s_i$. After recovering $T-1$ partial secrets we can aggregate them with the appropriate lagrange coefficients to reconstruct the full secret key.

Notice that to solve the linear system we need to work modulo each irreducible factor of $x^n + 1$ in $\mathbb{Z}_q$ and then apply the CRT.

During the competition another (unintended) solution was found, which managed to exploit the fact that the errors were really small and there wasn't a query limit: collecting enough $y_i$ it was possible to recover the secret error $e_i$ (and therefore $s_i$) directly using statistics. This solution still required quite a bit of fiddling due to the timeout.

## Exploit

```py
#!/usr/bin/env sage
from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler
from hashlib import sha256
from random import sample
from pwn import remote, process
from gmpy2 import iroot

HOST, PORT = 'procyon.challs.external.open.ecsc2024.it', '38313'

q = 3331157407
n = 256
k = 5
l = 4
T = 5
names = ['alice', 'bob', 'charlie', 'oscar', 'olivia', 'trent', 'victor', 'wendy']
verbose = False
target_msg = 'flag pls?'

def random_vector(ring, dim, distribution=None):
    if distribution == None:
        return vector(ring, [ring.random_element() for _ in range(dim)])
    return vector(ring, [distribution() for _ in range(dim)])

def vec_to_pol(v):
    return sum([vi*y^i for i, vi in enumerate(v)])

def pol_to_vec(p):
    return vector(Rq, p.list())

def SSSS(s, degree=T-1):
    s = vec_to_pol(s)
    P = s + sum([RRq.random_element()*z^i for i in range(1, degree+1)])
    for i,k_ in enumerate(users.keys()):
        si = pol_to_vec(P(i+1))
        ei = random_vector(Rq, k, D)
        users[k_] = (i+1, (si, ei))
    return

def H(mode, args):
    if mode == 'c':
        h = int.from_bytes(sha256(b'c' + str(args).encode()).digest(), 'big')
        ret, b = 0, 1
        while h:
            ret += (h&1)*b
            b *= x
            h >>= 1
        return ret
    elif mode == 'com':
        return sha256(b'com' + str(args).encode()).hexdigest()
    else:
        raise Exception('[!] mode not implemented')

def recv_pubkey_and_share():
    rows = []
    for _ in range(k+1):
        rows.append([Rq(thing) for thing in chall.recvline(False).decode()[1:-1].split(', ')])
    
    t = vector(Rq, rows[-1])
    rows = rows[:-1]
    A = matrix(Rq, rows)

    chall.recvuntil(b'yours:\n')
    share0 = int(chall.recvline(False).decode())
    share1 = vector(Rq, chall.recvline(False).decode()[1:-1].split(', '))
    share2 = vector(Rq, chall.recvline(False).decode()[1:-1].split(', '))
    my_share = (share0, (share1, share2))

    return A, t, my_share

def sign(users, msg):
    sign_data = {}
    chall.sendline(b'1')
    chall.sendline(', '.join(users).encode())
    chall.sendlineafter(b'What do you want to sign? > ', msg.encode())

    for _ in range(len(users)):
        user = chall.recvuntil(b'commits to ').decode()[len('[+] '):].split(' ')[0]
        com = chall.recvline(False).decode()
        sign_data[user] = {}
        sign_data[user]['com'] = com
        if verbose:
            print(f'{user = }, {com = }')
    
    sign_data['you'] = {}

    my_ri = random_vector(Rq, l, D)
    sign_data['you']['ri'] = my_ri

    my_ei1 = random_vector(Rq, k, D)
    sign_data['you']['ei1'] = my_ei1

    my_wi = A*my_ri + my_ei1
    sign_data['you']['wi'] = my_wi

    my_com = H('com', my_wi)
    sign_data['you']['com'] = my_com

    chall.sendlineafter(b'What is your commitment? > ', my_com.encode())

    for _ in range(len(users)):
        user = chall.recvuntil(b'reveals ').decode()[len('[+] '):].split(' ')[0]
        wi = vector(Rq, chall.recvline(False).decode()[1:-1].split(', '))
        sign_data[user]['wi'] = wi
        if verbose:
            print(f'{user = }, {wi = }')
    
    chall.sendlineafter(b'Please reveal your wi too! > ', str(my_wi).encode())

    w = sum([sign_data[user]['wi'] for user in sign_data], zero_vector(Rq, k))
    c = H('c', (vk, msg, w))
    idxs = [int.from_bytes(sha256(user.encode()).digest(), 'big')%q for user in sign_data]

    for _ in range(len(users)):
        user = chall.recvuntil(b'responds with ').decode()[len('[+] '):].split(' ')[0]
        resp0, resp1 = chall.recvline(False).decode()[2:-2].split('), (')
        respi = (vector(Rq, resp0.split(', ')), vector(Rq, resp1.split(', ')))
        sign_data[user]['response'] = respi
        if verbose:
            print(f'{user = }, {respi = }')
    
    i = my_share[0]
    lam_i = prod([Rq(-j)/Rq(i-j) for j in idxs if i != j])
    si, ei = my_share[1]
    zi = c*lam_i*si + sign_data['you']['ri']
    yi = c*ei + sign_data['you']['ei1']
    respi = (zi, yi)
    sign_data['you']['response'] = respi

    chall.sendlineafter(b'First component of your response > ', str(zi).encode())
    chall.sendlineafter(b'Second component of your response > ', str(yi).encode())

    z_final = sum([sign_data[user]['response'][0] for user in sign_data], zero_vector(Rq, l))
    y_final = sum([sign_data[user]['response'][1] for user in sign_data], zero_vector(Rq, k))
    y_final += (w - (A*z_final + y_final - c*t))

    final_signature = (c, z_final, y_final)

    chall.recvuntil(b'[+] Congrats! The complete signature is:\n')
    c1 = Rq(chall.recvline(False).decode())
    z_final1 = vector(Rq, chall.recvline(False).decode()[1:-1].split(', '))
    y_final1 = vector(Rq, chall.recvline(False).decode()[1:-1].split(', '))

    assert c == c1
    assert z_final == z_final1
    assert y_final == y_final1

    return c, z_final, y_final, sign_data

def calc_lams(frens, me=False):
    if me:
        users = frens + ['you']
    else:
        users = frens
    idxs = [int.from_bytes(sha256(name.encode()).digest(), 'big')%q for name in users]
    lams = {}
    for name in users:
        i = int.from_bytes(sha256(name.encode()).digest(), 'big')%q
        lams[name] = prod([Rq(-j)/Rq(i-j) for j in idxs if i != j])
    return lams

def verify(msg, sig):
    chall.sendline(b'2')
    c, z, y = sig
    chall.sendlineafter(b'Message? > ', msg.encode())
    chall.sendlineafter(b'First component of the signature > ', str(c).encode())
    chall.sendlineafter(b'Second component of the signature > ', str(z).encode())
    chall.sendlineafter(b'Third component of the signature > ', str(y).encode())

    return chall.recvline(False).decode()

def conv_mat(mat, v, F):
    mat1 = []
    for i,row in enumerate(mat):
        mat1.append([])
        for j,coso in enumerate(row):
            mat1[i].append(sum([v^ii * el for ii, el in enumerate(coso.list())]))
    return matrix(F, mat1)

def conv_vec(vec, v, F):
    vec1 = []
    for i,coso in enumerate(vec):
        vec1.append(sum([v^ii * el for ii, el in enumerate(coso.list())]))
    return vector(F, vec1)

def norm_pol_squared(p):
    coefs = [int(c) for c in p.list()]
    coefs = [c if c < q//2 else c-q for c in coefs]
    return sum(c**2 for c in coefs)

def norm(v):
    return int(iroot(int(sum(norm_pol_squared(p) for p in v)), 2)[0])

def get_input_and_check(length):
    inp = chall.recvline(False).decode()[1:-1].split(', ') # just send it as str(wi)
    assert len(inp) == length, '[!] Please be friendly >:('
    return vector(Rq, inp)

with remote(HOST, PORT) as chall:
    Fq.<a> = PolynomialRing(Zmod(q))

    facs = list(factor(a^n + 1))
    assert all([f[1] == 1 for f in facs])
    facs = [f[0] for f in facs]

    Rq.<x> = Fq.quotient(a^n + 1)
    RRq.<y> = PolynomialRing(Rq)
    RRRq.<z> = PolynomialRing(RRq)
    D = DiscreteGaussianDistributionPolynomialSampler(Rq, n=n, sigma = 3.0)

    frens = sample(names, T)
    msg = 'ciao!'
    chall.sendlineafter(b'public key > ', b'a')
    A, t, my_share = recv_pubkey_and_share()
    vk = (A, t)

    print('[+] sign 1')
    c, z, y, sign_data = sign(frens, msg)
    lams0 = calc_lams(frens, me=True)

    print('[+] sign 2')
    frens_save = frens[:]
    frens.append(choice([name for name in names if name not in frens]))
    c1, z1, y1, sign_data1 = sign(frens, msg)
    lams1 = calc_lams(frens, me=True)

    print('[+] recovering secrets')
    recovered_keys = {}
    for fren in frens_save:
        wi0, c0 = sign_data[fren]['wi'], c
        zi0, yi0 = sign_data[fren]['response']
        lam0 = lams0[fren]
        ti0 = (A*zi0 + yi0 - wi0)/c0


        wi1, c1 = sign_data1[fren]['wi'], c1
        zi1, yi1 = sign_data1[fren]['response']
        lam1 = lams1[fren]
        ti1 = (A*zi1 + yi1 - wi1)/c1

        tgt = ti1 - ti0
        mat = (lam1-lam0)*A

        sols = []
        for f in facs:
            Rq_.<xx> = Fq.quotient(f)
            mat_ = conv_mat(mat, xx, Rq_)
            tgt_ = conv_vec(tgt, xx, Rq_)
            si_ = mat_.solve_right(tgt_)
            sols.append(conv_vec(si_, a, Fq))

        recovered_keys[fren] = vector(Rq, [crt([s[i] for s in sols], facs) for i in range(mat.ncols())])
    
    lams0 = calc_lams(frens_save)
    recovered_secret = sum(lams0[name]*recovered_keys[name] for name in frens_save)
    recovered_secret = vector(Rq, recovered_secret)
    print(f'{norm(recovered_secret) = }')

    r = random_vector(Rq, l, D)
    e1 = random_vector(Rq, k, D)
    w = A*r + e1
    c = H('c', (vk, target_msg, w))
    e = t - A*recovered_secret

    z = c*recovered_secret + r
    y = c*e + e1

    verif_cond = c == H('c', (vk, target_msg, A*z + y - c*t))
    print(f'{verif_cond = }')
    print(f'{norm(z) = }, {norm(y) = }')

    hope = verify(target_msg, (c, z, y))
    if 'TeamItaly' in hope:
        print(f'\n{hope}')
        exit()
    print(hope, chall.recvall(timeout=1))
```
