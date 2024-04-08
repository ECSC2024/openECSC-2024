import hashlib
import os
import base64
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import json
from flask import Flask, request, render_template, redirect, url_for, request, make_response
from werkzeug.middleware.proxy_fix import ProxyFix

cookie_key = os.getenv('SESSION_SECRET', 'f0a46dcbee6ee62df42e22f4dc9fc779').encode()

app = Flask(__name__)
app.wsgi_app = ProxyFix(
    app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1
)

def get_flag(addr):
    return os.getenv('FLAG', 'flag{placeholder}')

def decrypt_session(session):
    try:
        session = base64.b64decode(session)
        iv = session[:16]
        cipher = session[16:]

        aes = AES.new(cookie_key, AES.MODE_CBC, iv)

        decrypted = aes.decrypt(cipher)
        decrypted = unpad(decrypted, 16)
        return decrypted.decode('utf-8')
    except:
        return None


def make_new_state():
    return {
        'next': random.randint(1, 3),
        'visited': []
    }


def get_state():
    # Get cookie
    session = request.cookies.get('session')
    if session is None:
        return make_new_state()

    # Decrypt cookie
    state = decrypt_session(session)
    if state is None:
        return make_new_state()

    # Get state from cookie
    try:
        return json.loads(state)
    except:
        return make_new_state()


def set_state(state):
    # Encrypt state
    iv = os.urandom(16)
    aes = AES.new(cookie_key, AES.MODE_CBC, iv)
    state = json.dumps(state).encode('utf-8')
    state = pad(state, 16)
    cipher = aes.encrypt(state)
    session = iv + cipher
    session = base64.b64encode(session).decode('utf-8')

    return session


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        state = get_state()
        print(state)

        if len(state['visited']) == 10:
            return render_template("flag.html", flag=get_flag(request.remote_addr))

        response = make_response(render_template("index.html"))
        response.set_cookie('session', set_state(state))
        return response
    
    if request.method == "POST":
        state = get_state()
        print(state)
        choice = request.form.get('choice')

        # If no choice, retry
        if choice is None:
            return redirect(url_for('index'))

        # If invalid choice, retry        
        try:
            choice = int(choice)
        except:
            return redirect(url_for('index'))

        if len(state['visited']) == 10:
            response =  make_response(render_template("flag.html", flag=get_flag(request.remote_addr)))
            response.set_cookie('session', set_state(state))
            return response

        # If choice is the correct one, add to list
        if state['next'] == choice:
            state['visited'].append({
                'choice': choice
            })
            state['next'] = random.randint(1, 3)
        else:
            state = make_new_state()

        response = make_response(redirect(url_for('index')))
        response.set_cookie('session', set_state(state))
        return response


if __name__ == "__main__":
    app.run(debug=True)