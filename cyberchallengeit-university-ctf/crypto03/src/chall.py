#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC
import os

flag = os.getenv('FLAG', 'CCIT{redacted}')
BLOCK_SIZE = AES.block_size

secret = os.urandom(16)
market_db = {}
balance = 1

def xor(a, b):
    return bytes([x ^ y for x,y in zip(a,b)])

def encrypt(k, m):
    cipher = AES.new(k, AES.MODE_ECB)
    return cipher.encrypt(m)

def compression(h, m):
    return xor(encrypt(xor(m, h), xor(m, h)), h)

def h(m):
    msg = pad(m, BLOCK_SIZE)
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    res = (0x13371337).to_bytes(BLOCK_SIZE, "big")

    for block in blocks:
        res = compression(res, block)
    return res

def create_tag(secret, item):
    hashed_m = h(item)
    hmac = HMAC.new(secret)
    hmac.update(hashed_m)
    return hmac.digest()

def verify_tag(secret, item, tag):
    hashed_m = h(item)
    hmac = HMAC.new(secret)
    hmac.update(hashed_m)
    try:
        hmac.verify(tag)
        return True
    except:
        return False

def insert_item(item):
    item_id = os.urandom(16).hex()
    market_db[item_id] = item

def show_items():
    for item_id in market_db:
        item = market_db[item_id]
        if item[0] != flag:
            print(f"{item_id}: {item}")
        else:
            print(f"{item_id}: (flag, 100)")

def buy_item(item_id):
    global balance
    if item_id not in market_db:
        print("Item not found!")
    elif balance < market_db[item_id][1]:
        print("Not enough money!")
    else:
        balance -= market_db[item_id][1]
        item = market_db[item_id]
        full_item = bytes.fromhex(item_id) + item[0].encode()
        tag = create_tag(secret, full_item)
        print(f"Here is your new purchase: {full_item.hex()}")
        print(f"and the tag for refund: {tag.hex()}")

def get_refund(full_item, tag):
    global balance
    item_id = full_item[:16].hex()
    if not verify_tag(secret, full_item, tag):
        print("Are you trying to fool me??")
    elif item_id not in market_db:
        print("You didn't buy that from us...")
    elif market_db[item_id][0] == flag:
        print("Sorry, flags are not refundable")
    else:
        item = market_db[item_id]
        balance += item[1]
        market_db.pop(item_id) # faulty duck or goose
        insert_item(item) # there is always need of ducks and geese
        print("You got your money back!")


items = [(flag, 100), ("duck", 1), ("goose", 2)]

for item in items:
    insert_item(item)

while True:
    print()
    print(f"Your balance: {balance}")
    print()
    print("What do you want to do?")
    print("1. Show items")
    print("2. Buy")
    print("3. Get a refund")

    choice = int(input("> ").strip())

    if choice not in [1, 2, 3]:
        print("Bye!")
        break

    if choice == 1:
        show_items()
    elif choice == 2:
        item_id = input("item_id: ")
        buy_item(item_id)
    elif choice == 3:
        full_item = bytes.fromhex(input("full_item: "))
        tag = bytes.fromhex(input("tag: "))
        get_refund(full_item, tag)