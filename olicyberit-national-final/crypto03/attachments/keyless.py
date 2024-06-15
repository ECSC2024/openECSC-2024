#!/usr/bin/env python3

import os
from hashlib import sha256
from Crypto.Util.number import getPrime
import random

flag = os.getenv('FLAG', 'flag{redacted}')

class SigningServer:
    def __init__(self):
        self.p = getPrime(1024)
        self.q = getPrime(1024)
        self.n = self.p*self.q
        self.e = 65537
        self.d = pow(self.e, -1, (self.p-1)*(self.q-1))
    
    def h(self, m):
        return int.from_bytes(sha256(m).digest(), "big")
    
    def sign(self, username, message):
        sid = pow(self.h(username), self.d, self.n)
        r = random.getrandbits(1024)
        s1 = pow(r, self.e, self.n)
        s2 = (sid*pow(r, self.h(message), self.n)) % self.n

        return (s1, s2)
    
    def verify(self, username, message, signature):
        s1, s2 = signature
        if not (1 < s1 < self.n-1 and 1 < s2 < self.n-1):
            return False
        return pow(s2, self.e, self.n) == (self.h(username)*pow(s1, self.h(message), self.n)) % self.n

server = SigningServer()
print(f"Server's public key: {(server.n, server.e)}")

while True:
    print()
    print("1. Sign something")
    print("2. Verify yourself")
    print("3. Send a message to user")

    choice = int(input("> "))

    if choice == 1:
        user = input("Please enter your name: ")
        if user == "admin":
            print("I don't think so...")
        else:
            msg = input("Please enter your message: ")
            print(f"Here's your signature: {server.sign(user.encode(), msg.encode())}")
    elif choice == 2:
        user = input("Please enter your name: ")
        msg = f"Verifying myself: I am {user} on OliCyber.IT"
        s1 = int(input("First component of the signature: "))
        s2 = int(input("Second component of the signature: "))

        if server.verify(user.encode(), msg.encode(), (s1,s2)):
            if user == "admin":
                print(f"Welcome back {user}! Here's your flag: {flag}")
            else:
                print(f"Welcome back {user}!")   
        else:
            print("That does not seem to be true...")   
    elif choice == 3:
        msg = input("Your message: ")
        user_to = input("Recipient: ")

        # TODO: implement something to send messages for real..

        print("Message sent!")
        print(f"User {user_to} says: ACK")
        print(f"Message signature: {server.sign(user_to.encode(), b'ACK')}")
    else:
        print("Bye!")
        break

