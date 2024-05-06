#!/usr/bin/env python3

import logging
import os
import requests

logging.disable()

URL = os.environ.get("URL", "http://remotediagnostics.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

r = requests.get(URL)
r.raise_for_status()

assert 'Spawn' in r.text

print('openECSC{i_cannot_find_a_fun_flag_and_chatgpt_is_not_helping_00000000}')
