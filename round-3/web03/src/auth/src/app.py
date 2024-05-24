from flask import Flask, abort, request, jsonify, send_file
from sqlitedict import SqliteDict
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import jwt
from functools import wraps
import os
import json

app = Flask(__name__)

DB_PATH = os.environ.get('DB_PATH', ':memory:')
db = lambda: SqliteDict(DB_PATH, outer_stack=False, encode=json.dumps, decode=json.loads)

if os.path.isfile('id_rsa.pem'):
    with open('id_rsa.pem', 'r') as fd:
        PRIVATE_KEY = fd.read()
    

def validate(func):
    @wraps(func)
    def d():
        if not request.is_json:
            abort(400)
        data = request.json
        
        if 'username' not in data or 'password' not in data:
            abort(400)
        username, password = data['username'], data['password']
        
        if type(username) is not str or type(password) is not str:
            abort(400)
        
        
        with db() as users:
            result = func(users, username, password)
        
        return jsonify(result)
    return d


@app.post('/login')
@validate
def login(users, username, password):
    if username not in users:
        return {'status': False, 'err': 'User not found.'}
    user_pwd = users[username]
    
    if not check_password_hash(user_pwd, password):
        return {'status': False, 'err': 'Wrong password.'}

    token = jwt.encode({"username": username}, PRIVATE_KEY, algorithm="RS256")
    
    return {'status': True, 'token': token}


@app.post('/register')
@validate
def register(users, username, password):
    if username in users:
        return {'status': False, 'err': 'User already registered.'}
    
    pwd_hash = generate_password_hash(password)
    users[username] = pwd_hash
    users.commit()

    token = jwt.encode({"username": username}, PRIVATE_KEY, algorithm="RS256")
    return {'status': True, 'token': token}
    


@app.cli.command("install")
def install():

    print('Initializing db.')
    with db() as users:
        users.commit()

    os.chown(DB_PATH, 1000, 1000)
    os.chown('.', 1000, 1000)
    os.chmod(DB_PATH, 0o765)
    

    if os.path.isfile('id_rsa.pem') and os.path.isfile('id_rsa.pub'):
        return

    print('Generating RSA keys...')
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
        )

    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo  
    )

    with open('id_rsa.pem', 'w') as fd:
        fd.write(pem_private_key.decode())
    
    with open('id_rsa.pub', 'w') as fd:
        fd.write(pem_public_key.decode())
    
    print('Keys generated')

    

    
