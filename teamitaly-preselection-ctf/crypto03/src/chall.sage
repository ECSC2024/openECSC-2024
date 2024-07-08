#!/usr/bin/env sage
from sage.stats.distributions.discrete_gaussian_polynomial import DiscreteGaussianDistributionPolynomialSampler
from hashlib import sha256
from random import sample
from os import getenv

q = 3331157407
n = 256
k = 5
l = 4
T = 5

names = ['alice', 'bob', 'charlie', 'oscar', 'olivia', 'trent', 'victor', 'wendy']
assert len(names) >= T
users = {name: None for name in names}
users['you'] = None
target_msg = 'flag pls?'

Fq.<a> = PolynomialRing(Zmod(q))
Rq.<x> = Fq.quotient(a^n + 1)
RRq.<y> = PolynomialRing(Rq)
RRRq.<z> = PolynomialRing(RRq)
D = DiscreteGaussianDistributionPolynomialSampler(Rq, n=n, sigma=3.0)

def random_vector(ring, dim, distribution=None):
    if distribution == None:
        return vector(ring, [ring.random_element() for _ in range(dim)])
    return vector(ring, [distribution() for _ in range(dim)])

def vec_to_pol(v):
    return sum([vi*y^i for i, vi in enumerate(v)])

def pol_to_vec(p, length):
    p = p.list()
    if len(p) != length:
        p = p + [0 for _ in range(length-len(p))]
    return vector(Rq, p)

def SSSS(sk, degree=T-1):
    s, e = sk
    s = vec_to_pol(s)
    P = s + sum([RRq.random_element(degree=l-1)*z^i for i in range(1, degree+1)])
    for name in users.keys():
        idx = int.from_bytes(sha256(name.encode()).digest(), 'big')%q
        assert idx != 0, '[!] nope'
        si = pol_to_vec(P(idx), l)
        ei = random_vector(Rq, k, D)
        users[name] = (idx, (si, ei))
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

def commit(user):
    sign_data[user] = {}

    ri = random_vector(Rq, l, D)
    sign_data[user]['ri'] = ri

    ei1 = random_vector(Rq, k, D)
    sign_data[user]['ei1'] = ei1

    wi = A*ri + ei1
    sign_data[user]['wi'] = wi

    com = H('com', wi)
    sign_data[user]['com'] = com

    print(f'[+] {user} commits to {com}')

def check_correctness():
    for user in sign_data:
        assert sign_data[user]['com'] == H('com', sign_data[user]['wi']), '[!] something\'s wrong..'
    return

def respond(w, c, idxs):
    for user in sign_data:
        if user == 'you':
            continue

        i = users[user][0]
        lam_i = prod([Rq(-j)/Rq(i-j) for j in idxs if i != j])
        si, ei = users[user][1]
        zi = c*lam_i*si + sign_data[user]['ri']
        yi = c*ei + sign_data[user]['ei1']
        respi = (zi, yi)
        sign_data[user]['response'] = respi

        print(f'[+] {user} responds with {respi}')

def get_input_and_check(m, length):
    inp = input(m)[1:-1].split(', ') # just send it as str(wi)
    assert len(inp) == length, '[!] Please be friendly >:('
    return vector(Rq, inp)

def sign():
    frens = input('Who do you want to sign with? > ').split(', ')
    assert len(frens) >= T-1, f'[!] you need at least {T-1} friends to compute a signature! :(' 
    assert all([fren in names for fren in frens]), f'[!] there\'s someone not so friendly in that list..'

    msg = input('What do you want to sign? > ')
    assert msg != target_msg, '[!] Wait, that\'s illegal!'

    for user in frens:
        commit(user)
    
    sign_data['you'] = {}
    sign_data['you']['com'] = input('What is your commitment? > ')

    for user in frens:
        print(f'[+] {user} reveals {sign_data[user]["wi"]}')
    
    sign_data['you']['wi'] = get_input_and_check('Please reveal your wi too! > ', k)

    check_correctness()

    w = sum([sign_data[user]['wi'] for user in sign_data], zero_vector(Rq, k))
    c = H('c', (vk, msg, w))
    idxs = [users[user][0] for user in sign_data]

    respond(w, c, idxs)

    z_you = get_input_and_check('First component of your response > ', l)
    y_you = get_input_and_check('Second component of your response > ', k)
    sign_data['you']['response'] = (z_you, y_you)

    z_final = sum([sign_data[user]['response'][0] for user in sign_data], zero_vector(Rq, l))
    y_final = sum([sign_data[user]['response'][1] for user in sign_data], zero_vector(Rq, k))
    y_final += (w - (A*z_final + y_final - c*t))

    final_signature = (c, z_final, y_final)
    final_signature_s = "\n".join(str(f) for f in final_signature)
    print(f'[+] Congrats! The complete signature is:\n{final_signature_s}')

def verify():
    msg = input('Message? > ')
    c = Rq(input('First component of the signature > '))
    z = get_input_and_check('Second component of the signature > ', l)
    y = get_input_and_check('Third component of the signature > ', k)

    assert c == H('c', (vk, msg, A*z + y - c*t)), '[!] Signature doesn\'t verify!'

    if msg == target_msg:
        print(getenv('FLAG', 'TeamItaly{REDACTED}'))
    else:
        print('[+] Signature ok :)')
    return

def recv_pubkey_and_share():
    # you're welcome
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

def banner():
    print('Welcome to our new animal friendly distributed signing service!')
    print(f'You have a lot of crypto friends waiting for you! Their names are {", ".join(names)}.')
    print('(It is cryptographically immoral to give away one\'s share, sorry! They are still your friends tho)')
    input('Please press a key to receive the public key > ')
    print("\n".join([str(row.list()) for row in A]))
    print(t)
    print()
    print('Sharing is caring! Here\'s yours:')
    print(users['you'][0])
    print(users['you'][1][0])
    print(users['you'][1][1])
    return

def menu():
    print('''
What do you want to do?
1) sign with friends! :)
2) verify''')
    return input('> ')

A = random_matrix(Rq, k, l)
s = random_vector(Rq, l, D)
e = random_vector(Rq, k, D)
t = A*s + e
vk = (A, t)
sk = (s, e)
SSSS(sk)

banner()
while 1:
    try:
        choice = menu()
        if choice == '1':
            sign_data = {}
            sign()
        elif choice == '2':
            verify()
        else:
            print('bye!')
            exit()
    except Exception as e:
        print(f'Exception: {e}')
        break
