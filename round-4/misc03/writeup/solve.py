#!/usr/bin/env python
# coding: utf-8

import os
import time
import random
import string
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
import glob

# import snapshots in `pool/test` and `zfs set snapdir=visible pool/test`

files = [f for f in glob.glob("/pool/test/.zfs/snapshot/**/*[!test_file_write].txt", recursive=True)]

def find_seed(test_file):
    ti_c = os.path.getctime(test_file)
    return int(ti_c)

def read_key(key_filename, nonce):
    with open(key_filename) as f:
        encoded_xored_key = f.read()
    xored_key = base64.b64decode(encoded_xored_key)
    key = bytes(a ^ b for a, b in zip(nonce, xored_key))
    return key

def decrypt(filename, key):
    with open(filename,'rb') as f:
        nonce = f.read(16)
        data = f.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(data).decode('ascii')

def find_file(r):
    r = str(r)
    for file in files:
        if r in file:
            return file
    return None

def find_key_and_decrypt(seed, path, lenght=16):
    print(f"Start finding key file with seed: {seed}")
    while True:
        random.seed(seed)
        num_files = random.randint(100,200)
        for item in range(0, num_files):
            r = random.randint(0,65535)
            s = ''.join(random.choices(string.ascii_lowercase, k=lenght)).encode("ascii")
    
        r = random.randint(0,65535)
        key_filename = find_file(r)
        #key_filename = os.path.join(path,str(r)+".txt")
        nonce = ''.join(random.choices(string.ascii_lowercase, k=lenght)).encode("ascii")
    
        if key_filename is not None and os.path.exists(key_filename):
            print(f"FOUND CANDIDATE KEY FILE: {key_filename}")
            try:
                key = read_key(key_filename, nonce)            # READING THE KEY AND DECODING IT
                decrypted_configuration = decrypt(os.path.join(path,'configuration.encrypted'),key) # DECRYPTING CONFIGURATION FILE
                print(decrypted_configuration)
                configuration = json.loads(decrypted_configuration)
                print("CONFIGURATION DECRYPTED")
                return configuration
            except:
                break
                print("CANNOT DECRYPT WITH CANDIDATE KEY")
                seed = seed + 1
                print(f"Retrying with seed: {seed}")     
        else:
            seed = seed + 1
            print(f"Retrying with seed: {seed}")



if __name__ == "__main__":
    
    path = "/pool/test/challenge"
    seed = find_seed(os.path.join(path,'test_file_write.txt')) # GET CREATION TIME FROM THE FILE WRITTEN TO CHECK WRITING PERMISSION
    configuration = find_key_and_decrypt(seed,path)  # USING THE CREATION TIME AS SEED FOR THE PRNG IDENTIFY THE NAME OF THE FILE THAT CONTAINS THE KEY FOR ENCRYPTION
    print(f"Descrypted Configuration:\n {configuration}")
