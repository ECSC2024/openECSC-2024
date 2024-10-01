#!/usr/bin/env python3

import dataclasses
import functools
import operator
import os

import xoflib
from sage.all import QQ, ZZ, Field, PolynomialQuotientRing, Zmod, gcd, lcm
from sage.rings.polynomial.polynomial_quotient_ring import PolynomialQuotientRing_generic as TPoly

flag = os.getenv("FLAG", "openECSC{redacted}").encode()


def xor(a, b):
    assert len(a) == len(b)
    return bytes(map(operator.xor, a, b))


def xof_range(xof: xoflib.Sponge256, lower: int, upper: int) -> int:
    nbits = (upper - lower).bit_length()
    nbytes = (nbits + 7) // 8
    while True:
        res = int.from_bytes(xof.read(nbytes)) + lower
        if lower <= res < upper:
            return res


def sample_ternary_poly_coeffs(xof: xoflib.Sponge256, N: int, one: int, minus_one: int) -> list[int]:
    res = [0 for _ in range(N)]
    while sum(res) < one:
        res[xof_range(xof, 0, N)] = 1
    while sum(res) > one - minus_one:
        idx = xof_range(xof, 0, N)
        if not res[idx]:
            res[idx] = -1
    return res


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

    def keygen(self, seed: bytes) -> "Key":
        xof = xoflib.shake256(seed)
        while True:
            f = sample_ternary_poly_coeffs(xof, self.N, self.df, self.df - 1)
            finv = self.RQQ(f) ** -1
            denom = lcm(c.denominator() for c in finv.list())
            if gcd(denom, self.q) == gcd(denom, self.p) == 1:
                break
        fp = self.Rp(f)**-1
        fq = self.Rq(f)**-1
        g = sample_ternary_poly_coeffs(xof, self.N, self.dg, self.dg)
        h = self.p * fq * self.Rq(g)
        return Key(params=self, h=h, f=f, fp=fp, xof=xof)


@dataclasses.dataclass
class Key:
    params: Params
    h: TPoly
    f: TPoly
    fp: TPoly
    xof: xoflib.Sponge256

    def encrypt1(self, m: list[int]) -> list[int]:
        assert all(-1 <= x <= 1 for x in m)
        assert len(m) <= self.params.N
        m = self.params.Rq(m)
        r = self.params.Rq(sample_ternary_poly_coeffs(self.xof, self.params.N, self.params.dr, self.params.dr))
        return (self.h * r + m).list()

    def encrypt2(self, m: list[int]) -> list[int]:
        assert all(-1 <= x <= 1 for x in m)
        assert len(m) <= self.params.N
        m = self.params.Rq(m)
        r = self.params.Rq(sample_ternary_poly_coeffs(self.xof, self.params.N, self.params.dr, self.params.dr))
        φ = self.params.Rq([xof_range(self.xof, -1, 2) for _ in range(self.params.N)])
        e = r * self.h + φ
        E = φ * e + m
        return e.list() + E.list()

    def encrypt3(self, m_: list[int]) -> list[int]:
        assert all(-1 <= x <= 1 for x in m_)
        assert len(m_) <= self.params.H
        z = [xof_range(self.xof, -1, 2) for _ in range(self.params.N - self.params.H)]
        m: TPoly = self.params.Rp(m_ + z)
        m += self.params.Rp(z).lift()(self.params.Rp.gen() + 1) ** 6
        m = self.params.Rq([x.lift_centered() for x in m.list()])
        r = self.params.Rq(sample_ternary_poly_coeffs(self.xof, self.params.N, self.params.dr, self.params.dr))
        return (self.h * r + m).list()


PARAMS = Params(N=107, p=3, q=67, df=15, dg=12, dr=5, H=91)


def encode_share(share, maxlen) -> list[int]:
    res = [int(x) - 1 for x in ZZ(int.from_bytes(share)).digits(3, padto=maxlen)]
    assert len(res) <= maxlen
    return res


def p1(share: bytes):
    msg = encode_share(share, PARAMS.N)
    k = PARAMS.keygen(share)
    print(k.h)
    for _ in range(2 * PARAMS.N):
        print(k.encrypt1(msg))

# Leftovers from an old version of the challenge, feel free to try them
# def p2(share: bytes):
#     msg = encode_share(share, PARAMS.N)
#     k = PARAMS.keygen(share)
#     for _ in range(2 * PARAMS.N):
#         k = PARAMS.keygen(k.xof.read(32))
#         print(k.h)
#         print(k.encrypt1(msg))


# def p3(share: bytes):
#     msg = encode_share(share, PARAMS.N)
#     k = PARAMS.keygen(share)
#     print(k.h)
#     for _ in range(2 * PARAMS.N):
#         print(k.encrypt2(msg))


# def p4(share: bytes):
#     msg = encode_share(share, PARAMS.N)
#     k = PARAMS.keygen(share)
#     for _ in range(2 * PARAMS.N):
#         k = PARAMS.keygen(k.xof.read(32))
#         print(k.h)
#         print(k.encrypt2(msg))


def p5(share: bytes):
    msg = encode_share(share, PARAMS.H)
    k = PARAMS.keygen(share)
    print(k.h)
    for _ in range(10):
        print(k.encrypt3(msg))


# For an extra challenge
# def p6(share: bytes):
#     msg = encode_share(share, PARAMS.H)
#     k = PARAMS.keygen(share)
#     for _ in range(10):
#         k = PARAMS.keygen(k.xof.read(32))
#         print(k.h)
#         print(k.encrypt3(msg))


ps = [1, 5]
share_xof = xoflib.shake256(flag[:-10])
key = xoflib.shake256(flag).read(16)
shares = [share_xof.read(len(key)) for _ in range(len(ps) - 1)]
shares.insert(0, functools.reduce(xor, shares, key))
for i, share in zip(ps, shares):
    locals()[f"p{i}"](share)

print(xor(flag, xoflib.shake256(key).read(len(flag))).hex())
