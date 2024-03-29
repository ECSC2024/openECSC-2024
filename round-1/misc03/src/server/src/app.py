import os
from flask import Flask, request
import binascii
import app_pb2

app = Flask(__name__)


@app.get("/get-flag")
def get_flag():
    protobuf = request.args.get("protobuf")
    if protobuf is None:
        return "Please provide a protobuf message"

    try:
        gf = app_pb2.GetFlag()
        gf.ParseFromString(bytes(bytearray.fromhex(protobuf)))
    except:
        return "Invalid protobuf message: " + protobuf

    username = gf.username
    if username is None or username == "":
        return "Please provide a username"

    if username == "admin":
        return (
            "Hello, "
            + username
            + "! You are admin. The flag is: "
            + os.environ["FLAG"].replace(
                "RANDOMPART", binascii.b2a_hex(os.urandom(4)).decode()
            )
        )

    return "Hello, " + username + "! You are not admin."
