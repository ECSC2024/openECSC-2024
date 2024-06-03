# CyberChallenge.IT 2024 - University CTF

## [crypto] Hash-based market (11 solves)

Just the usual boring market app... But with hashes!

`nc hashmarket.challs.external.open.ecsc2024.it 38206`

Author: Matteo Rossi <@mr96>

## Overview

The challenge is a classic market app: we have a balance (initially of 1 coin) and some items are sold in the market. In particular, the market starts with 3 items:

- a duck, with the cost of 1 coin
- a goose, with the cost of 2 coins
- a flag, with the cost of 100 coins

Our objective is, of course, to buy the flag.

The market has 3 options:

- showing items
- buying items
- getting a refund for already bought items, with the exception of the flag, that is not refundable

## Solution

Let's analyze the market options:

- the "show items" option prints the items, their cost and a unique id of the item in the market
- the "buy" option allows us to buy items using their id, and gives us the "full item" (id plus item content) and a tag for the refund option
- the "get a refund" option takes full items and tags, and gives back the cost of the item if the item id is actually in the market

The solution path is quite straightforward: we somehow want to craft tags to get refunds without buying items. Notice also that items that get refunded are then removed from the market and re-inserted with a different id, so we can not refund an item an arbitary number of times, but we need to repeatedly forge tags.

How is the tag created?

```py
def create_tag(secret, item):
    hashed_m = h(item)
    hmac = HMAC.new(secret)
    hmac.update(hashed_m)
    return hmac.digest()
```

This function takes a secret (16 random bytes generated in a safe way by the server), an item, and performs an HMAC. Crucially, the HMAC is not perormed directly on the item, but on its hash with a custom hash function `h`. This means that a collision on `h` is enough to have a collision in the tag.

The last important thing to notice is that, when asking for a refund, the first 16 bytes of the full item are used as the item id, while the rest is not checked. This means that we can use multiple blocks to craft collisions, where the first block must be our target item id and the rest is not relevant for the server.

So, a possible attack strategy is the following:

- buy a duck for 1 coin, obtaining a tag
- ask for a refund of a goose for 2 coins, crafting a message starting with the item id of the goose that has the same digest of the full item of the duck under `h`, and using the tag obtained at the previous point
- now we have 2 coins instead of 1; repeat 100 times to buy the flag

So, the last step is obtaining collisions.

How does the hash function work? The only relevant code is the following, where `encrypt(key, message)` is just an AES-ECB encryption.

```py
def compression(h, m):
    return xor(encrypt(xor(m, h), xor(m, h)), h)

def h(m):
    msg = pad(m, BLOCK_SIZE)
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    res = (0x13371337).to_bytes(BLOCK_SIZE, "big")

    for block in blocks:
        res = compression(res, block)
    return res
```

The strategy for collisions is the following:

- we start with the target item id (the goose)
- we craft a block that "resets" the state of the hash function to its initial value
- we append the full item we want to collide with (the duck)

For the second step, we only need to "undo" the first call to the compression. This is done by calculating it locally and XOR-ing it back to the first block and the initial state that we want to reach. The code to do it is the following, where `item_id` is the target item id, and `full_item` is the full item we want to collide with.

```py
def construct_payload(item_id, full_item):
    h0 = (0x13371337).to_bytes(BLOCK_SIZE, "big")
    m0 = bytes.fromhex(item_id)
    h1 = xor(encrypt(xor(m0, h0), xor(m0, h0)), h0)
    m1 = xor(h1, xor(m0, h0))
    return (m0 + m1).hex() + full_item
```

Full exploit is given below.

## Exploit

```py
#!/usr/bin/env python3
import os

from pwn import remote
from Crypto.Cipher import AES

HOST = os.environ.get("HOST", "hashmarket.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38206))

BLOCK_SIZE = AES.block_size

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])


def encrypt(k, m):
    cipher = AES.new(k, AES.MODE_ECB)
    return cipher.encrypt(m)


def compression(h, m):
    return xor(encrypt(xor(m, h), xor(m, h)), h)


def get_items():
    chall.sendlineafter(b"> ", b"1")
    items = {}
    for _ in range(3):
        item_id, item = chall.recvline().decode().strip().split(": ")
        item_price = int(item.split(", ")[1][:-1])
        items[item_price] = item_id
    return items


def buy_item(item_id):
    chall.sendlineafter(b"> ", b"2")
    chall.sendlineafter(b": ", item_id.encode())
    full_item = chall.recvline().decode().strip().split(": ")[1]
    tag = chall.recvline().decode().strip().split(": ")[1]
    return full_item, tag


def get_refund(full_item, tag):
    chall.sendlineafter(b"> ", b"3")
    chall.sendlineafter(b": ", full_item.encode())
    chall.sendlineafter(b": ", tag.encode())
    chall.recvline().decode()


def construct_payload(item_id, full_item):
    h0 = (0x13371337).to_bytes(BLOCK_SIZE, "big")
    m0 = bytes.fromhex(item_id)
    h1 = xor(encrypt(xor(m0, h0), xor(m0, h0)), h0)
    m1 = xor(h1, xor(m0, h0))
    return (m0 + m1).hex() + full_item

with remote(HOST, PORT) as chall:
    items = get_items()
    for _ in range(100):
        duck, tag = buy_item(items[1])
        payload = construct_payload(items[2], duck)
        get_refund(payload, tag)
        items = get_items()
    flag, tag = buy_item(items[100])
    print(bytes.fromhex(flag)[16:].decode())
```
