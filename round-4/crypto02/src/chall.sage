#!/usr/bin/env sage
from random import SystemRandom
from functools import partial
from hashlib import sha256
from json import loads, dumps
from Crypto.Util.Padding import pad
import traceback

BITS = 128
BYTES = ceil(BITS/8)
flag = os.getenv('FLAG', 'openECSC{redacted}')

def intify(x):
    return list(map(int, x))

def strify(x):
    return list(map(str, x))

class BN:
    def __init__(self, m):
        rng = SystemRandom()
        randrange = lambda *args: rng.randrange(*args)

        R.<x> = ZZ[]
        P = 36*x^4 + 36*x^3 + 24*x^2 + 6*x + 1
        
        bits = lambda x: ceil(log(P(-x), 2).n())
        a, b = randrange(2^(m//4 - 5)), randrange(2^(m//4 - 1), 2^(m//4))
        assert bits(a) <= m and bits(b) >= m

        x = (a+b)//2
        while (now := bits(x)) != m:
            if x == a or x == b:
                raise Exception(f'Suitable x not found for {m} bits curve, {now = }')
            if now < m:
                a = x
            else:
                b = x
            x = (a+b)//2
        
        while 1:
            t, p = 6*x^2 + 1, P(-x)
            n = p + 1 - t

            if is_prime(p) and is_prime(n):
                break
            
            p = P(x)
            n = p + 1 - t

            if is_prime(p) and is_prime(n):
                break
            
            x += 1

        self.t  = t
        self.p  = p
        self.n  = n
        self.Fp = GF(p)

        b = 0
        while 1:
            while 1:
                b += 1
                if kronecker(b + 1, self.p) == 1:
                    break
                    
            EFp = EllipticCurve(self.Fp, [0, b])
            G1  = EFp.lift_x(1)

            if self.n*G1 == EFp([0, 1, 0]):
                break
        
        assert EFp.order() == self.n, 'Wrong EFp order'

        for k in range(1, 13):
            if (self.p^k - 1)%self.n == 0:
                if k != 12:
                    raise Exception(f'Wrong EFp embedding degree {k = }')
                else:
                    break
        else:
            raise Exception('Wrong EFp embedding degree, unknown')
        
        self.k   = k
        self.b   = b
        self.EFp = EFp
        
        Fp2.<a> = GF(self.p^2)
        self.Fp2 = Fp2

        for lam in self.Fp:
            try:
                lam.nth_root(3)
            except ValueError:
                break
        
        while 1:
            mu = self.Fp2.random_element()
            try:
                mu.nth_root(2)
            except ValueError:
                break
        
        eps  = (self.Fp2(lam^2)*mu^3)^-1
        EFp2 = EllipticCurve(self.Fp2,  [0, self.b/eps])
        
        if (EFp2.order() % n) == 0:
            self.EFp2 = EFp2
        else:
            eps = eps^5
            self.EFp2 = EllipticCurve(self.Fp2,  [0, self.b/eps])
        
        EFp2_ord = self.EFp2.order()
        assert EFp2_ord % self.n == 0, f'Didn\'t manage to find a twist with an appropriate subgroup'

        self.eps = eps
        self.O_EFp  = self.EFp([0, 1, 0])
        self.O_EFp2 = self.EFp2([0, 1, 0])
        
        cof = EFp2_ord//self.n
        while 1:
            G2 = cof * self.EFp2.random_element()
            if G2 != self.O_EFp2 and self.n * G2 == self.O_EFp2:
                break

        self.G2 = G2

        Fp2u.<u> = self.Fp2[]
        Fp12.<z> = (u^6 - eps).root_field()

        self.Fp2u   = Fp2u
        self.Fp12   = Fp12
        self.z      = z
        self.EFp12  = EllipticCurve(self.Fp12, [0, self.b])
        self.G1     = G1

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
    
class PKG:
    def __init__(self, bits):
        self.curve = BN(bits)

        self.r = SystemRandom()

        self.p = self.curve.n

        self._a, g, g2 = [self.rng() for _ in range(3)]

        self.g  =           g * self.curve.G2
        self.g1 = self._a * g * self.curve.G1

        self.g2_G1 = g2 * self.curve.G1
        self.g2_G2 = g2 * self.curve.G2

        self.h = self.rng() * self.curve.G2
        
        self.u_, self.m_ =  [self.rng() * self.curve.G1 for _ in range(2)]
        self.U,  self.M  = [[self.rng() * self.curve.G1 for _ in range(bits)] for _ in range(2)]

        self.params = {
            # G1 elements
            'g1' : intify(self.g1.xy()),
            'u_' : intify(self.u_.xy()),
            'U'  : [intify(ui.xy()) for ui in self.U],
            'm_' : intify(self.m_),
            'M'  : [intify(mi.xy()) for mi in self.M],

            # G2 elements
            'g'  : strify(self.g.xy()),
            'g2' : strify(self.g2_G2.xy()),
            'h'  : strify(self.h.xy()),

            # curve params
            'curve': self.curve.json
        }

        print('### broadcasting public parameters ###')
        print(dumps(self.params), '\n')

    def rng(self):
        return int(self.r.randrange(self.p))
    
    def H(self, x):
        return int.from_bytes(sha256(x).digest()[:BYTES], 'big') % self.p
    
    def H1(self, *args):
        return self.H(b'||'.join(list(map(lambda x: str(x).encode(), args))) + b'||\x01')
    
    def H2(self, P):
        return self.H(str(P).encode() + b'||\x02')
    
    def extract(self, uid):
        uid = intify(f'{int(uid, 16):0{BITS}b}')
        ru = self.rng()
        du0 = (self._a * self.g2_G1 + ru * sum([self.u_] + [self.U[i] for i in range(BITS) if uid[i]], self.curve.O_EFp))
        du1 = ru * self.g
        return (du0, du1)
    
class User:
    def __init__(self, pkg, uid):
        self.curve = pkg.curve
        self.r     = pkg.r
        self.p     = pkg.p

        # decode pkg params
        # G1 elements
        self.g1, self.u_, self.m_, =  [self.curve.EFp(pkg.params[k])              for k in ['g1', 'u_', 'm_']]
        self.U,  self.M            = [[self.curve.EFp(v)  for v in pkg.params[k]] for k in ['U',  'M']]
        # G2 elements
        self.g, self.g2, self.h    =  [self.curve.EFp2(pkg.params[k])             for k in ['g', 'g2', 'h']]

        self.uid = intify(f'{int(uid, 16):0{BITS}b}')
        self.sk  = pkg.extract(uid)

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
    global conversation_logs
    c_ret = []
    for c_ in c:
        s1, s2, s3, s4, s5, s6 = c_
        s1     = curve.Fp12(s1)
        s3, s5 = list(map(curve.EFp, [s3, s5]))
        s2, s4 = list(map(curve.EFp2,[s2, s4]))
        s6     = s6 % curve.n
        c_ret.append([s1, s2, s3, s4, s5, s6])
        hsh = sha256(b'||'.join(list(map(lambda x: str(x).encode(), c_ret)))).hexdigest()
        if hsh in conversation_logs['hashes']:
            raise Exception('no replays please!')
        conversation_logs['hashes'].append(hsh)
    return c_ret

def get_uid(uname):
    return sha256(uname).digest()[:BYTES].hex()

def menu():
    print('''Choose an option:
1) register
2) display conversation logs
3) deliver a message to the system
0) quit
''')
    return input('> ')
    
def register():
    global db
    uname = input('username: ').encode()
    uid = get_uid(uname)
    if uid in db:
        raise Exception('user already exists')
    
    user = User(pkg, uid)
    db[uid] = (user, uname)
    print(f'registration successful! private key:')
    print(dumps(intify(user.sk[0].xy())))
    print(dumps(strify(user.sk[1].xy())))
    return

def display_conversation_logs():
    print(dumps(conversation_logs), '\n')
    return

def deliver_message():
    global conversation_logs
    message = loads(input('message: '))
    
    if any(k not in message for k in ['sender', 'receiver', 'ciphertext']):
        raise Exception('please send the message to be delivered as a correctly formatted json')

    uname1, uname2 = message['sender'].encode(), message['receiver'].encode()
    uid1, uid2 = get_uid(uname1), get_uid(uname2)

    if uid1 not in db or uid2 not in db:
        raise Exception('user(s) not found')
    
    user1, user2 = db[uid1], db[uid2]
    check, ptxt = user2.unencrygn(decode_ciphertext(message['ciphertext'], user2.curve), user1)
    log = {'sender': uname1.decode(), 'receiver': uname2.decode(), 'ciphertext': message['ciphertext'], 'verifies': check}
    if check:
        log['plaintext'] = str(ptxt)
    else:
        log['plaintext'] = str([])
    
    conversation_logs['logs'].append(log)
    print('message logged!\n')
    return

def send_and_log(sender_uname, receiver_uname, message):
    global conversation_logs
    sender_uid, receiver_uid = get_uid(sender_uname), get_uid(receiver_uname)

    sender, receiver = db[sender_uid], db[receiver_uid]
    ctxt = sender.encrygn(message, receiver)
    check, ptxt = receiver.unencrygn(decode_ciphertext(ctxt, receiver.curve), sender)

    log = {'sender': 'alice', 'receiver': 'bob', 'ciphertext': ctxt, 'verifies': check}

    if check:
        if flag in message.decode():
            log['plaintext'] = '## redacted ##'
        else:
            log['plaintext'] = str(ptxt)
    else:
        log['plaintext'] = str([])

    conversation_logs['logs'].append(log)
    return


db = {}
conversation_logs = {'logs': [], 'hashes': []}

pkg = PKG(BITS)

alice = User(pkg, get_uid(b'alice'))
bob   = User(pkg, get_uid(b'bob'))

db[get_uid(b'alice')] = alice
db[get_uid(b'bob')]   = bob

send_and_log(b'alice', b'bob', f'hey bob, I hope the system deletes this lol {flag}'.encode())
send_and_log(b'bob', b'alice', f'lol yea that seems like sensitive information..'.encode())

while 1:
    try:
        choice = menu()
        match choice:
            case '1':
                register()
            case '2':
                display_conversation_logs()
            case '3':
                deliver_message()
            case _:
                print('bye!')
                exit()

    except Exception as exc:
        # print(traceback.format_exc())
        print(f'something went wrong! {exc = }')