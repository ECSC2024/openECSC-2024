import os

import requests
from flask import Flask, request

from protoless import parse_message

app = Flask(__name__)

SERVER_HOST = os.getenv("SERVER_HOST", "server")


@app.route("/")
def index():
    return "The challenge works, now read the code!"


@app.get("/get-flag")
def get_flag():
    protobuf = request.args.get("protobuf")
    if protobuf is None:
        return "Please provide a protobuf message"

    try:
        gf = parse_message(bytes(bytearray.fromhex(protobuf)))
    except:
        return "Invalid protobuf message: " + protobuf

    if 1 not in gf:
        return "Please provide a username"
    username = gf[1]["value"]
    if username is None:
        return "Please provide a username"

    if username == b"admin":
        return "Cannot be admin"

    return requests.get(f"http://{SERVER_HOST}/get-flag?protobuf=" + protobuf).text
