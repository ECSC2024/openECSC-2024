import dataclasses
import functools
import itertools
import operator
import sys
from collections.abc import Callable, Iterator
from typing import Any

import xoflib

try:
    from tqdm import tqdm, trange
except ImportError:

    def trange(*args, **kw):
        return range(*args)

    def tqdm(x, **kw):
        return x


from sage.all import QQ, ZZ, Field, Matrix, PolynomialQuotientRing, PolynomialRing, Zmod, vector
from sage.rings.polynomial.polynomial_quotient_ring import PolynomialQuotientRing_generic as TPoly


def xor(a, b):
    assert len(a) == len(b)
    return bytes(map(operator.xor, a, b))


@dataclasses.dataclass(frozen=True)
class Params:
    N: int
    q: int
    p: int
    df: int
    dg: int
    dr: int
    H: int

    @property
    @functools.cache
    def Zq(self) -> Field:
        return Zmod(self.q)

    @property
    @functools.cache
    def Rq(self) -> TPoly:
        R = self.Zq["x"]
        return PolynomialQuotientRing(R, R.gen() ** self.N - 1)

    @property
    @functools.cache
    def Zp(self) -> Field:
        return Zmod(self.p)

    @property
    @functools.cache
    def Rp(self) -> TPoly:
        R = self.Zp["x"]
        return PolynomialQuotientRing(R, R.gen() ** self.N - 1)

    @property
    @functools.cache
    def RQQ(self) -> TPoly:
        R = QQ["x"]
        return PolynomialQuotientRing(R, R.gen() ** self.N - 1)


PARAMS = Params(N=107, p=3, q=67, df=15, dg=12, dr=5, H=91)


def read_poly(f: Iterator[str]) -> TPoly:
    line = next(f).strip()
    res = [0 for _ in range(PARAMS.N)]
    for term in line.split(" + "):
        if term == "xbar":
            coef = exp = 1
        elif "xbar" not in term:
            coef = int(term)
            exp = 0
        elif "xbar^" not in term:
            coef = int(term[:-5])
            exp = 1
        elif "*" not in term:
            coef = 1
            exp = int(term[5:])
        else:
            coef, exp = map(int, term.split("*xbar^"))
        res[exp] = coef
    return PARAMS.Rq(res)


def read_enc1(f: Iterator[str]) -> TPoly:
    line = next(f).strip()
    line = line.strip()
    return PARAMS.Rq(list(map(int, line[1:-1].split(", "))))


def read_enc2(f: Iterator[str]) -> tuple[TPoly, TPoly]:
    line = next(f).strip()
    coeffs = list(map(int, line[1:-1].split(", ")))
    c1 = PARAMS.Rq(coeffs[: len(coeffs) // 2])
    c2 = PARAMS.Rq(coeffs[len(coeffs) // 2 :])
    return (c1, c2)


def repeat(r: Callable[[Iterator[str]], Any], n: int) -> Callable[[Iterator[str]], list[Any]]:
    return lambda f: [r(f) for _ in range(n)]


def reads(*rs: Callable[[Iterator[str]], Any]) -> Callable[[Iterator[str]], list[Any]]:
    return lambda f: [r(f) for r in rs]


def decode(p: TPoly | list[int]) -> bytes:
    if not isinstance(p, list):
        p = p.list()
    return sum(((d.lift_centered() + 1) % 3) * 3**i for i, d in enumerate(p)).to_bytes(16)


def p1(h: TPoly, cs: list[TPoly]) -> TPoly:
    known_ones = set()
    known_minus = set()
    known_not_ones = set()
    known_not_minus = set()
    h1 = h.matrix().pseudoinverse()
    for c in tqdm(cs[1:], desc="p1"):
        r_diff = (h1 * (c - cs[0]).matrix())[0]
        for i, rd in enumerate(r_diff):
            if rd == 2:
                known_minus.add(i)
            elif rd == -2:
                known_ones.add(i)
            elif rd == 1:
                known_not_ones.add(i)
            elif rd == -1:
                known_not_minus.add(i)
            elif rd == 0:
                # Ehh
                pass
            else:
                assert False
        if len(known_ones) == len(known_minus) == PARAMS.dr:
            break
    x = PARAMS.Rq.gen()
    # If not, might need to use the restrictions + some brute force
    assert len(known_ones) == len(known_minus) == PARAMS.dr
    r = sum(x**i for i in known_ones) - sum(x**i for i in known_minus)
    return cs[0] - h * r


# def p2(*cs: tuple[TPoly, TPoly]) -> TPoly:
#     # https://eprint.iacr.org/2011/590.pdf
#     PR = PolynomialRing(
#         PARAMS.Zq, names=[f"m{i}" for i in range(PARAMS.N)] + [f"x{i}" for i in range(1, PARAMS.N // 2 + 1)]
#     )
#     msym = vector(PR, PR.gens())[: PARAMS.N]
#     x = vector(PR, PR.gens())[PARAMS.N :]
#     mat = [[1] * PARAMS.N + [0] * len(x)]
#     vec = [cs[0][1].lift()(1)]
#     for h, c in tqdm(cs, desc="p2"):
#         h1 = h.matrix().pseudoinverse()
#         a = vector(list((h1.T * h1)[-1])[::-1])
#         b = h1 * c.matrix()[0]
#         d = 2 * PARAMS.dr
#         s = d - b.dot_product(b)
#         w = b * h1
#         lhs = sum(2 * (a[i] - a[0]) * x[i - 1] for i in range(1, PARAMS.N // 2 + 1)) - sum(
#             2 * w[i] * msym[i] for i in range(PARAMS.N)
#         )
#         rhs = s - a[0] * c.lift()(1) ** 2
#         mat.append([lhs.coefficient(v) for v in PR.gens()])
#         vec.append(rhs)
#     sol = Matrix(PARAMS.Zq, mat).solve_right(vector(PARAMS.Zq, vec))
#     return PARAMS.Rq(list(sol)[: PARAMS.N])


# def p3(h: TPoly, cs: list[tuple[TPoly, TPoly]]) -> TPoly:
#     downstream: list[tuple[TPoly, TPoly]] = []
#     for e, E in tqdm(cs, desc="p3"):
#         # E - e * e == φ * e + m - (r * h + φ) * e
#         #           == - r h e + m
#         downstream.append((-h * e, E - e * e))
#     return p2(*downstream)


# def p4(*cs: tuple[TPoly, tuple[TPoly, TPoly]]) -> TPoly:
#     downstream: list[tuple[TPoly, TPoly]] = []
#     for h, (e, E) in tqdm(cs, desc="p4"):
#         # E - e * e == φ * e + m - (r * h + φ) * e
#         #           == - r h e + m
#         downstream.append((-h * e, E - e * e))
#     return p2(*downstream)


def CVP(M, target):
    M = Matrix(QQ, M).LLL(algorithm="pari")
    target = vector(QQ, target)
    G = M.gram_schmidt()[0]
    diff = target
    for i in reversed(range(M.nrows())):
        diff -= M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
    return target - diff


def unpad(m: TPoly) -> TPoly:
    m = PARAMS.Rp([x.lift_centered() for x in m.list()])
    x = PARAMS.Rp.gen()
    if 6 * (m.lift().degree() - PARAMS.H + 1) <= PARAMS.H:
        z = PARAMS.Rp(m.list()[PARAMS.H :])
        return (m - z * x**PARAMS.H - z.lift()(x + 1) ** 6).list()[: PARAMS.H]
    else:
        high = 6 * (PARAMS.N - PARAMS.H)
        skipped = high - PARAMS.H
        z_high = PARAMS.Rp(m.list()[high:]) * x**skipped
        z = PARAMS.Rp((PARAMS.Rp(m.list()) - z_high.lift()(x + 1) ** 6).list()[PARAMS.H :])
        return (m - z * x**PARAMS.H - z.lift()(x + 1) ** 6).list()[: PARAMS.H]


def intersect(M1, M2):
    D1 = M1.inverse().T
    D2 = M2.inverse().T
    D, denom = D1.stack(D2)._clear_denom()
    return (D.hermite_form(algorithm="pari", include_zero_rows=False) / denom).inverse().T


def p5(h: TPoly, cs: list[TPoly]) -> TPoly:
    S = [i for i in range(PARAMS.H) if i % 3 != 0]
    one_indices = set(range(PARAMS.N))
    minus_indices = set(range(PARAMS.N))
    for i in trange(len(cs) - 1, desc="p5"):
        cbar = cs[i] - cs[0]
        λ1 = 100000
        λ2 = 100000
        inter = None
        for j in S:
            M = Matrix.identity(PARAMS.N + 2)
            M[0, 0] = λ1 * PARAMS.q
            M[1, 0] = -λ1 * int(cbar[j])
            M[2:, 0] = λ1 * h.matrix().T[j].change_ring(ZZ)
            M[2:, 1] = λ2
            if inter is None:
                inter = M
            else:
                inter = intersect(M, inter)
        try:
            rbar = next(
                r[1] * r
                for r in inter.LLL()
                if r[0] == 0 and r[1] in [-1, 1] and abs(sum(r)) == 1 and sum(map(abs, r)) == 1 + 4 * PARAMS.dr
            )[2:]
        except StopIteration:
            continue

        if all(x in {-2, -1, 0, 1, 2} for x in rbar) and sum(map(abs, rbar)) == 4 * PARAMS.dr:
            new_one = {i for i, x in enumerate(rbar) if x in {-1, -2}}
            new_minus = {i for i, x in enumerate(rbar) if x in {1, 2}}
            one_indices &= new_one
            minus_indices &= new_minus
            # We could maybe eliminate some more by ensuring new_minus if not in one (and vice versa)
            # but that becomes a bit more of a pain to actually test that's valid
        if len(one_indices) == len(minus_indices) == PARAMS.dr:
            break
    for ones in itertools.combinations(one_indices, PARAMS.dr):
        for minus in itertools.combinations(minus_indices, PARAMS.dr):
            r = PARAMS.Rq([1 if i in ones else -1 if i in minus else 0 for i in range(PARAMS.N)])
            m = cs[0] - h * r
            if all(x.lift_centered() in {-1, 0, 1} for x in m.list()):
                return unpad(m)
    assert False, "Huhh?"


shares = []
with open(sys.argv[1]) as f:
    shares.append(decode(p1(*reads(read_poly, repeat(read_enc1, 2 * PARAMS.N))(f))))
    # shares.append(decode(p2(*repeat(reads(read_poly, read_enc1), 2 * PARAMS.N)(f))))
    # shares.append(decode(p3(*reads(read_poly, repeat(read_enc2, 2 * PARAMS.N))(f))))
    # shares.append(decode(p4(*repeat(reads(read_poly, read_enc2), 2 * PARAMS.N)(f))))
    shares.append(decode(p5(*reads(read_poly, repeat(read_enc1, 10))(f))))
    encflag = bytes.fromhex(next(f).strip())

key = functools.reduce(xor, shares)
flag = xor(xoflib.shake256(key).read(len(encflag)), encflag)
print(flag.decode())
