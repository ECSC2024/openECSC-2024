#!/usr/bin/env python3

import logging
import os
import requests
import re

logging.disable()

URL = os.environ.get("URL", "http://prettyplease.challs.olicyber.it")
if URL.endswith("/"):
    URL = URL[:-1]

r = requests.post(URL, data={'how': 'pretty please'})
r.raise_for_status()

flag = re.search(r'flag{.*}', r.text).group(0)
print(flag)