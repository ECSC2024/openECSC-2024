#!/usr/bin/env python3

import logging
import os

import requests

logging.disable()

URL = os.environ.get("URL", "http://192.168.100.3")
if URL.endswith("/"):
    URL = URL[:-1]

r = requests.get(URL)
r.raise_for_status()

print('flag{jSf*ck_15n7_4_Gr34T_w4Y_t0_0bfusc4t3_3e08fd31}')
