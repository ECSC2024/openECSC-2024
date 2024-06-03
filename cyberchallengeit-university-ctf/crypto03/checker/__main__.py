#!/usr/bin/env python3

import logging
import os

from pwn import remote
from Crypto.Cipher import AES

logging.disable()

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
    # print(chall.recvline().decode())
    chall.recvline().decode()


def construct_payload(item_id, full_item):
    h0 = (0x13371337).to_bytes(BLOCK_SIZE, "big")
    m0 = bytes.fromhex(item_id)
    h1 = xor(encrypt(xor(m0, h0), xor(m0, h0)), h0)
    m1 = xor(h1, xor(m0, h0))
    return (m0 + m1).hex() + full_item


# with process(["python", "new_market.py"]) as chall:
with remote(HOST, PORT) as chall:
    items = get_items()
    # print(items)
    for _ in range(100):
        duck, tag = buy_item(items[1])
        payload = construct_payload(items[2], duck)
        get_refund(payload, tag)
        items = get_items()
    flag, tag = buy_item(items[100])
    print(bytes.fromhex(flag)[16:].decode())
