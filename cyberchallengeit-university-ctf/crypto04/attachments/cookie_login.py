#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes
from hashlib import md5
import os
import random

flag = os.getenv('FLAG', 'CCIT{redacted}')

def legendre(h, p):
    if h % p == 0:
        return 0
    elif pow(h, (p-1)//2, p) == 1:
        return 1
    else:
        return -1

def hash_msg(m):
    return bytes([0xbb]*90) + os.urandom(2) + bytes([0xba]) + md5(m).digest() + bytes([0xcc])

class CookieLogin:
    def __init__(self, n_bits):
        self.generate_keys(n_bits)
        self.users = [b"admin"]

    def generate_keys(self, n_bits):
        self.p = self.q = 1

        while self.p%8 != 3:
            self.p = getPrime(n_bits)
        
        while self.q%8 != 7:
            self.q = getPrime(n_bits)

        self.n = self.p*self.q
        self.c = pow(self.q, -1, self.p)

    def create_cookie(self, user):
        mask = random.randint(2, self.n-2)
        inv_mask = pow(mask, -1, self.n)
        mask = pow(mask, 2, self.n)
        h = bytes_to_long(hash_msg(user))*mask

        if legendre(h, self.p) * legendre(h, self.q) != 1:
            h = h // 2

        v1 = pow(h, (self.p+1)//4, self.p)
        v2 = pow(h, (self.q+1)//4, self.q)
        s = (self.q*((self.c * (v1 - v2)) % self.p) + v2) % self.n
        s = s*inv_mask % self.n
        return min(s, self.n - s)

    def verify_cookie(self, cookie, user):
        if cookie < 0 or cookie > (self.n-1)//2:
            return False
        
        t1 = pow(cookie, 2, self.n)
        t2 = self.n - t1

        if t1 % 16 == 12:
            val = t1
        elif t1 % 8 == 6:
            val = 2*t1
        elif t2 % 16 == 12:
            val = t2
        elif t2 % 8 == 6:
            val = 2*t2
        else:
            return False
        
        return bytes_to_long(hash_msg(user)) % 2**136 == val % 2**136

    def register(self, user):
        if user in self.users:
            print("User already registered!")
        else:
            self.users.append(user)
            cookie = self.create_cookie(user)
            print(f"User registered! Here is your cookie: {cookie}")

    def login(self, user, cookie):
        if user not in self.users:
            print("Please register")
        elif not self.verify_cookie(cookie, user):
            print("Cookie not valid!")
        elif user == b"admin":
            print(f"Welcome back admin! Here is your flag: {flag}")
        else:
            print("Not much to do here...")

website = CookieLogin(512)
print(f"{website.n = }")

while True:
    print()
    print("Hello! Our website is in development, but you can test our register/login functionality")
    print("1) Register")
    print("2) Login")
    choice = int(input("> "))

    if choice == 1:
        user = bytes.fromhex(input("Username: "))
        website.register(user)
    elif choice == 2:
        user = bytes.fromhex(input("Username: "))
        cookie = int(input("Cookie: "))
        website.login(user, cookie)

