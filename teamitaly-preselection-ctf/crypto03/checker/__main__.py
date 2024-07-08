

# This file was *autogenerated* from the file __main__.sage
from sage.all_cmdline import *   # import sage library

_sage_const_38313 = Integer(38313); _sage_const_3331157407 = Integer(3331157407); _sage_const_256 = Integer(256); _sage_const_5 = Integer(5); _sage_const_4 = Integer(4); _sage_const_1 = Integer(1); _sage_const_0 = Integer(0); _sage_const_2 = Integer(2); _sage_const_3p0 = RealNumber('3.0')#!/usr/bin/env sage

import logging
import os

logging.disable()

# For TCP connection
HOST = os.environ.get("HOST", "procyon.challs.external.open.ecsc2024.it")
PORT = os.environ.get("PORT", _sage_const_38313 )

from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler
from hashlib import sha256
from random import sample
from pwn import remote, process

q = _sage_const_3331157407 
n = _sage_const_256 
k = _sage_const_5 
l = _sage_const_4 
T = _sage_const_5 
names = ['alice', 'bob', 'charlie', 'oscar', 'olivia', 'trent', 'victor', 'wendy']
verbose = False
debug = False
target_msg = 'flag pls?'

def random_vector(ring, dim, distribution=None):
    if distribution == None:
        return vector(ring, [ring.random_element() for _ in range(dim)])
    return vector(ring, [distribution() for _ in range(dim)])

def vec_to_pol(v):
    return sum([vi*y**i for i, vi in enumerate(v)])

def pol_to_vec(p):
    return vector(Rq, p.list())

def SSSS(s, degree=T-_sage_const_1 ):
    s = vec_to_pol(s)
    P = s + sum([RRq.random_element()*z**i for i in range(_sage_const_1 , degree+_sage_const_1 )])
    for i,k_ in enumerate(users.keys()):
        si = pol_to_vec(P(i+_sage_const_1 ))
        ei = random_vector(Rq, k, D)
        users[k_] = (i+_sage_const_1 , (si, ei))
    return

def H(mode, args):
    if mode == 'c':
        h = int.from_bytes(sha256(b'c' + str(args).encode()).digest(), 'big')
        ret, b = _sage_const_0 , _sage_const_1 
        while h:
            ret += (h&_sage_const_1 )*b
            b *= x
            h >>= _sage_const_1 
        return ret
    elif mode == 'com':
        return sha256(b'com' + str(args).encode()).hexdigest()
    else:
        raise Exception('[!] mode not implemented')

def recv_pubkey_and_share():
    rows = []
    for _ in range(k+_sage_const_1 ):
        rows.append([Rq(thing) for thing in chall.recvline(False).decode()[_sage_const_1 :-_sage_const_1 ].split(', ')])
    
    t = vector(Rq, rows[-_sage_const_1 ])
    rows = rows[:-_sage_const_1 ]
    A = matrix(Rq, rows)

    chall.recvuntil(b'yours:\n')
    share0 = int(chall.recvline(False).decode())
    share1 = vector(Rq, chall.recvline(False).decode()[_sage_const_1 :-_sage_const_1 ].split(', '))
    share2 = vector(Rq, chall.recvline(False).decode()[_sage_const_1 :-_sage_const_1 ].split(', '))
    my_share = (share0, (share1, share2))

    return A, t, my_share

def sign(users, msg):
    sign_data = {}
    chall.sendline(b'1')
    chall.sendline(', '.join(users).encode())
    chall.sendlineafter(b'What do you want to sign? > ', msg.encode())

    for _ in range(len(users)):
        user = chall.recvuntil(b'commits to ').decode()[len('[+] '):].split(' ')[_sage_const_0 ]
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
        user = chall.recvuntil(b'reveals ').decode()[len('[+] '):].split(' ')[_sage_const_0 ]
        wi = vector(Rq, chall.recvline(False).decode()[_sage_const_1 :-_sage_const_1 ].split(', '))
        sign_data[user]['wi'] = wi
        if verbose:
            print(f'{user = }, {wi = }')
    
    chall.sendlineafter(b'Please reveal your wi too! > ', str(my_wi).encode())

    w = sum([sign_data[user]['wi'] for user in sign_data], zero_vector(Rq, k))
    c = H('c', (vk, msg, w))
    idxs = [int.from_bytes(sha256(user.encode()).digest(), 'big')%q for user in sign_data]

    for _ in range(len(users)):
        user = chall.recvuntil(b'responds with ').decode()[len('[+] '):].split(' ')[_sage_const_0 ]
        resp0, resp1 = chall.recvline(False).decode()[_sage_const_2 :-_sage_const_2 ].split('), (')
        respi = (vector(Rq, resp0.split(', ')), vector(Rq, resp1.split(', ')))
        sign_data[user]['response'] = respi
        if verbose:
            print(f'{user = }, {respi = }')
    
    i = my_share[_sage_const_0 ]
    lam_i = prod([Rq(-j)/Rq(i-j) for j in idxs if i != j])
    si, ei = my_share[_sage_const_1 ]
    zi = c*lam_i*si + sign_data['you']['ri']
    yi = c*ei + sign_data['you']['ei1']
    respi = (zi, yi)
    sign_data['you']['response'] = respi

    chall.sendlineafter(b'First component of your response > ', str(zi).encode())
    chall.sendlineafter(b'Second component of your response > ', str(yi).encode())

    z_final = sum([sign_data[user]['response'][_sage_const_0 ] for user in sign_data], zero_vector(Rq, l))
    y_final = sum([sign_data[user]['response'][_sage_const_1 ] for user in sign_data], zero_vector(Rq, k))
    y_final += (w - (A*z_final + y_final - c*t))

    final_signature = (c, z_final, y_final)

    chall.recvuntil(b'[+] Congrats! The complete signature is:\n')
    c1 = Rq(chall.recvline(False).decode())
    z_final1 = vector(Rq, chall.recvline(False).decode()[_sage_const_1 :-_sage_const_1 ].split(', '))
    y_final1 = vector(Rq, chall.recvline(False).decode()[_sage_const_1 :-_sage_const_1 ].split(', '))

    assert c == c1
    assert z_final == z_final1
    assert y_final == y_final1

    if debug:
        for user in users:
            sign_data[user]['true_si'] = vector(Rq, chall.recvline(False).decode()[_sage_const_1 :-_sage_const_1 ].split(', '))
            sign_data[user]['true_ei'] = vector(Rq, chall.recvline(False).decode()[_sage_const_1 :-_sage_const_1 ].split(', '))

    return c, z_final, y_final, sign_data

def calc_lams(frens):
    users = frens + ['you']
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
            mat1[i].append(sum([v**ii * el for ii, el in enumerate(coso.list())]))
    return matrix(F, mat1)

def conv_vec(vec, v, F):
    vec1 = []
    for i,coso in enumerate(vec):
        vec1.append(sum([v**ii * el for ii, el in enumerate(coso.list())]))
    return vector(F, vec1)

with remote(HOST, PORT) as chall:
    Fq = PolynomialRing(Zmod(q), names=('a',)); (a,) = Fq._first_ngens(1)

    facs = list(factor(a**n + _sage_const_1 ))
    assert all([f[_sage_const_1 ] == _sage_const_1  for f in facs])
    facs = [f[_sage_const_0 ] for f in facs]

    Rq = Fq.quotient(a**n + _sage_const_1 , names=('x',)); (x,) = Rq._first_ngens(1)
    RRq = PolynomialRing(Rq, names=('y',)); (y,) = RRq._first_ngens(1)
    RRRq = PolynomialRing(RRq, names=('z',)); (z,) = RRRq._first_ngens(1)
    D = DiscreteGaussianDistributionPolynomialSampler(Rq, n=n, sigma = _sage_const_3p0 )

    frens = sample(names, T)
    msg = 'ciao!'
    chall.sendlineafter(b'public key > ', b'a')
    A, t, my_share = recv_pubkey_and_share()
    vk = (A, t)

    c, z, y, sign_data = sign(frens, msg)
    lams0 = calc_lams(frens)

    frens_save = frens[:]
    frens.append(choice([name for name in names if name not in frens]))
    c1, z1, y1, sign_data1 = sign(frens, msg)
    lams1 = calc_lams(frens)

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
        if debug:
            true_si = sign_data[fren]['true_si']
            true_ei = sign_data[fren]['true_ei']
            assert ti0 == lam0*A*true_si + true_ei
            assert ti1 == lam1*A*true_si + true_ei
            print(f'[++] si, ei are solutions')

        sols = []
        for f in facs:
            Rq_ = Fq.quotient(f, names=('xx',)); (xx,) = Rq_._first_ngens(1)
            mat_ = conv_mat(mat, xx, Rq_)
            tgt_ = conv_vec(tgt, xx, Rq_)
            si_ = mat_.solve_right(tgt_)
            sols.append(conv_vec(si_, a, Fq))

        recovered_keys[fren] = vector(Rq, [crt([s[i] for s in sols], facs) for i in range(mat.ncols())])
        if debug:
            print(f'{recovered_keys[fren] == true_si = }')
    
    recovered_secret = sum(lam_i*si for lam_i, si in zip(lams0.values(), recovered_keys.values()))

    r = random_vector(Rq, l, D)
    e1 = random_vector(Rq, k, D)
    w = A*r + e1
    c = H('c', (vk, target_msg, w))
    e = t - A*recovered_secret

    z = c*recovered_secret + r
    y = c*e + e1

    verif_cond = c == H('c', (vk, target_msg, A*z + y - c*t))
    if debug:
        print(f'{verif_cond = }')

    hope = verify(target_msg, (c, z, y))
    if 'TeamItaly' in hope:
        print(hope)
        exit()
    print(hope, chall.recvall(timeout=_sage_const_1 ))

