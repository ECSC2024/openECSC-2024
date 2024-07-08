from flask import Flask, make_response, render_template, request, send_from_directory
from apscheduler.schedulers.background import BackgroundScheduler
from flask_socketio import SocketIO, send
from flask_cors import CORS
import random
import time
from functools import wraps
import os


FLAG = os.getenv("FLAG", "flag{redacted}")
app = Flask(__name__,static_folder=None)
socketio = SocketIO(app, debug=True, cors_allowed_origins='*', async_mode='eventlet')
CORS(app)

M = 1000000007

XJa3Fingerprint = [["ad1c90efe0f8e53d0b6fbab4c72ee22b", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"], ["8bcbf4ebb25c2a31e84ad6109865acc1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"], ["309f37a28597e08042dd6dabe2acfc6f", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"], ["aab27cdb8105b6ddfafce5ed76e99ac4", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"], ["a195b9c006fcb23ab9a2343b0871e362", "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"], ["b5001237acdf006056b409cc433726b0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"], ["ed3d2cb3d86125377f5a4d48e431af48", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"], ["ff965fb3c87efeabde869250629d5ef4", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"], ["986aaa763343033cb0b0022b32dedc19", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"], ["94bbfd48e7ab3b39444a0f396fb8e359", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"], ["1efcc65c18516dcd635f9f7cd69998eb", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"], ["df95207aca8123a44912ac85e49888b2", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"], ["b148d2c96e7b62ba0ec824a834bd3f24", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0"], ["773906b0efdefa24a7f2b8eb6985bf37", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"]]
XJa4Fingerprint = [["t13i1515h2_8daaf6152771_02713d6af862", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"], ["t13d1516h2_8daaf6152771_02713d6af862", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"], ["t13d1715h2_5b57614c22b0_7121afd63204", "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"], ["t13d1715h2_5b57614c22b0_5c2c66f702b0", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"], ["t13d1713h2_5b57614c22b0_748f4c70de1c", "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"], ["t13d2014h2_a09f3c656075_14788d8d241b", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"]]


sessions = {}


def cleaner():
    for k in list(sessions.keys()):
        if time.time() - sessions[k]['created_at'] > 120:
            del sessions[k]


scheduler = BackgroundScheduler()
job = scheduler.add_job(cleaner, 'interval', minutes=1)
scheduler.start()


def check_fingerprint(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        with app.app_context():
            kwargs['fingerprint_passed'] = True
            print(request.headers)
            if not('Backdoor' in request.headers and request.headers['Backdoor'] == '9eb52e6a6de0da03064ab8346e38788617deed8fc631549e3f10396a61afd31b'):
                if 'X-Ja4-Fingerprint' not in request.headers or request.headers['X-Ja4-Fingerprint'] not in [x[0] for x in XJa4Fingerprint]:
                    print('Ja4')
                    kwargs['fingerprint_passed'] = False
        
        return f(*args, **kwargs)

    return wrapper


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


def gen_pow(difficulty):

    match difficulty:
        case 0:
            lower = 1
            upper = 10
        case 1:
            lower = 15
            upper = 25
        case 2:
            lower = 25
            upper = 75
        case 3:
            lower = 75
            upper = 125
        case 4:
            lower = 150
            upper = 250
        case 5:
            lower = 250
            upper = 500
        case 6:
            lower = 500
            upper = 750
        case 7:
            lower = 800
            upper = 1000
        case 8:
            lower = 1300
            upper = 1600
        case 9:
            lower = 1600
            upper = 2000
        
    x = random.randint(lower, upper)
    y = random.randint(lower, upper)
    z = random.randint(lower, upper)
    n = random.randint(lower, upper)

    s = ((x+y) * pow(x+y+n*z, -1, M) * bincoeff(x+y+n*z, n)) % M
    return x, y, z, n, s


def gen_operation():
    a = random.randint(1, 500)
    b = random.randint(1, 500)
    o = random.choice('+*-/')
    match o:
        case '+':
            s = a+b
        case '-':
            s = a-b
        case '*':
            s = a*b
        case '/':
            s = a//b
    return a, b, o, s


@app.get('/')
@check_fingerprint
def home(fingerprint_passed=False):
    if fingerprint_passed:
        resp = make_response(render_template('home.html'))
    else:
        resp = make_response(render_template('banned.html'))

    return resp


@app.route('/static/<path:path>')
@check_fingerprint
def send_report(path, fingerprint_passed=False):
    if fingerprint_passed:
        return send_from_directory('static', path)
    else:
        return make_response("Browser not supported", 400)

@socketio.on("start")
@check_fingerprint
def start(fingerprint_passed=False):
    sid = request.sid
    if fingerprint_passed:
        x, y, z, n, p = gen_pow(0)
        a, b, o, s = gen_operation()
        sessions[sid] = {"created_at": time.time(), "pow": {"a": x, "b": y, "c": z, "d": n}, "pow_solution": p, "operation": {"a": a, "b": b, "o": o},  "operation_solution": s, "step": 0}
        send({"type": "calculation", "pow": {"a": x, "b": y, "c": z, "d": n}, "operation": {"a": a, "b": b, "o": o}}, room=sid)
    else:
        send({"type": "message", "message": "Browser not supported"})


@socketio.on("message")
def message(msg):
    t = time.time()
    sid = request.sid
    if sid not in sessions:
        send({"type": "message", "message": "Session not found!"})
    else:
        print(msg['pow_response'] == sessions[sid]['pow_solution'], msg['operation_response'] == sessions[sid]["operation_solution"], msg, sessions[sid])
        if msg['pow_response'] != sessions[sid]['pow_solution']:
            send({"type": "message", "message": "Wrong PoW!"})
        elif msg['operation_response'] != sessions[sid]["operation_solution"]:
            send({"type": "message", "message": "Wrong result!"})
        elif t - sessions[sid]["created_at"] > 100:
            send({"type": "message", "message": "Too slow!"})
        else:
            if sessions[sid]["step"] < 99:
                x, y, z, n, p = gen_pow(sessions[sid]["step"]//10)
                a, b, o, s = gen_operation()
                sessions[sid] = {"created_at": sessions[sid]["created_at"], "pow": {"a": x, "b": y, "c": z, "d": n}, "pow_solution": p, "operation": {"a": a, "b": b, "o": o},  "operation_solution": s, "step": sessions[sid]["step"]+1}
                send({"type": "calculation", "pow": {"a": x, "b": y, "c": z, "d": n}, "operation": {"a": a, "b": b, "o": o}}, room=sid)
            else:
                send({"type": "message", "message": FLAG % '805810a8'})
                del sessions[sid]


if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=5000)