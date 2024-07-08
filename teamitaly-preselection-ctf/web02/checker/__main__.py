#!/usr/bin/env python3

import logging
import os
import re

import requests

logging.disable()

URL = os.environ.get("URL", "https://xssthis.challs.external.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

r = requests.get(URL, verify=False)
r.raise_for_status()
sandbox = r.text.split(':')[1].strip()
assert re.match(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', sandbox)

print('TeamItaly{chrome://restart_1s_l0v3}')
