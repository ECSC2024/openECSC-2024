  #!/usr/bin/env python
# coding: utf-8

import base64
from Crypto.Cipher import AES
from datetime import datetime
from datetime import timezone
import json
import os
import re
import string
import random
import time


def test_file_write(path):
    test_string = "THIS IS A TEST\n"
    with open(os.path.join(path,"test_file_write.txt"),"w") as f:
        f.write(test_string)

    with open(os.path.join(path,"test_file_write.txt")) as f:
        data = f.read()

    if data == test_string:
        return True
    else:
        return False
    
s_num = 0
def write_file_and_snapshot(path, data, mode="w"):
    global s_num
    with open(path,mode) as f:
        f.write(data)
    os.system(f'sudo zfs snapshot pool@snap{s_num}')
    os.system(f'sudo rm -f {path}')
    if s_num == 0:
        os.system(f'sudo zfs send pool@snap{s_num} > ./snapshots/snap-{s_num}-.zfs')
    if s_num != 0:
        os.system(f'sudo zfs send -i pool@snap{s_num-1} pool@snap{s_num} > ./snapshots/snap-{s_num-1}-to-{s_num}.zfs')
    if s_num > 1:
        os.system(f'sudo zfs destroy pool@snap{s_num-2}')
    s_num += 1

def dump_key(path, key, lenght=16):
    now = datetime.now(timezone.utc)
    seed = int((now - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds())
    random.seed(seed)

    num_files = random.randint(100,200)
    
    for item in range(0, num_files):
        r = random.randint(0,65535)
        s = ''.join(random.choices(string.ascii_lowercase, k=lenght)).encode("ascii")
        write_file_and_snapshot(os.path.join(path,str(r)+".txt"), base64.b64encode(s).decode('ascii'))

    r = random.randint(0,65535)
    key_filename = os.path.join(path,str(r)+".txt")
    nonce = ''.join(random.choices(string.ascii_lowercase, k=lenght)).encode("ascii")
    xored_key = bytes(a ^ b for a, b in zip(nonce, key))
    write_file_and_snapshot(key_filename, base64.b64encode(xored_key).decode('ascii'))

    num_files = random.randint(100,200)

    for item in range(0, num_files):
        r = random.randint(0,65535)
        s = ''.join(random.choices(string.ascii_lowercase, k=lenght)).encode("ascii")
        write_file_and_snapshot(os.path.join(path,str(r)+".txt"), base64.b64encode(s).decode('ascii'))

    return key_filename, nonce

def create_config(url):
    obj = {"url":url}
    return json.dumps(obj)

def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext = cipher.encrypt(data)
    return ciphertext, cipher.nonce


if __name__ == "__main__":
    url = 'openECSC{hundreds_of_zfs_snapshots_for_a_single_file}'
    path = "/pool/challenge"
    if not os.path.exists(path):
        os.makedirs(path)

    if test_file_write(path):
        time.sleep(random.randint(1,10))
        key = ''.join(random.choices(string.ascii_lowercase, k=16)).encode('ascii')
        key_file, nonce = dump_key(path, key)
        config = create_config(url)
        chiphertext, nonce = encrypt_data(key, config.encode('ascii'))
        write_file_and_snapshot(os.path.join(path,'configuration.encrypted'), nonce+chiphertext, "wb")
        print(key_file)
        print(nonce)
    else:
        print("Cannot write to directory")
