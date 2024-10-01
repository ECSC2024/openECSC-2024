#!/usr/bin/env python3

import logging
import os
from exploit import exploit

logging.disable()

HOST = os.environ.get("HOST", "ctfteams.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 47004))

while True:
    try:
        flag = exploit(HOST, PORT)
        print(flag)
        break
    except:
        print('Retrying...')
