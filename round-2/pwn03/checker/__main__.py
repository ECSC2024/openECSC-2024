#!/usr/bin/env python3

import logging
import os
from exploit import exploit

logging.disable()

HOST = os.environ.get("HOST", "blindwriter.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38003))

flag = exploit(HOST, PORT)
print(flag)
