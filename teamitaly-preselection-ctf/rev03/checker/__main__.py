#!/usr/bin/env python3

import logging
import os
import requests
import socketio
import time

logging.disable()

M = 1000000007

def fac(n, k=1):
    r = 1
    while n > k:
        r *= n
        r %= M
        n -= 1
    return r


def bincoeff(n, k):
    if n < k:
        return 0
    
    fs = sorted([k, n-k])
    return (fac(n, fs[1]) * pow(fac(fs[0]), -1, M)) % M


def solve_pow(x, y, z, n):
    return ((x+y) * pow(x+y+n*z, -1, M) * bincoeff(x+y+n*z, n)) % M


def solve_op(a, b, o):
    match o:
        case '+':
            s = a+b
        case '-':
            s = a-b
        case '*':
            s = a*b
        case '/':
            s = a//b

    return s


URL = os.environ.get("URL", "https://calculationsx100.challs.external.open.ecsc2024.it:38314")
URL = URL.replace('http://', 'https://')
if URL.endswith("/"):
    URL = URL[:-1]

http_session = requests.Session()
http_session.verify = False
http_session.headers = {'Backdoor': '9eb52e6a6de0da03064ab8346e38788617deed8fc631549e3f10396a61afd31b'}
sio = socketio.Client(http_session=http_session)
i = 0

@sio.event
def connect():
    global i
    i = 0
    print('connection established')
    sio.emit("start")

@sio.event
def message(data):
    global i
    # print(f'message {i} received with {data}')
    i += 1

    if data["type"] == "calculation":
        pow_resp = solve_pow(data["pow"]["a"], data["pow"]["b"], data["pow"]["c"], data["pow"]["d"])
        op_resp  = solve_op(data["operation"]["a"], data["operation"]["b"], data["operation"]["o"])
        time.sleep(0.01)
        sio.send({'pow_response': pow_resp, "operation_response": op_resp})
    else:
        print(data["message"])
        sio.disconnect()


@sio.event
def disconnect():
    print('disconnected from server')


sio.connect(URL)
print('my sid is', sio.sid)
sio.wait()