#!/usr/bin/env python3

import logging
import os
import exploit

logging.disable()

HOST = os.environ.get("HOST", "aesbeta.challs.external.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38310))

flag = exploit.main(HOST, PORT)

print(flag)
