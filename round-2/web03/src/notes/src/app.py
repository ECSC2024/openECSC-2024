from flask import Flask, abort, request, jsonify, g
from sqlitedict import SqliteDict
import jwt
import os
import json
import requests
import secrets

app = Flask(__name__)

DB_PATH = os.environ.get('DB_PATH', ':memory:')

def get_db():
    return SqliteDict(DB_PATH, outer_stack=False, encode=json.dumps, decode=json.loads)

class AuthService:
    def __init__(self) -> None:
        self.key = False
        self.key_url = os.environ.get('AUTH_SERVICE', 'http://auth') + '/key'
    
    def verify(self, token):
        if not self.key:
            self._retrieve_key()
        try:
            data = jwt.decode(token, self.key, algorithms=["RS256"])
        except Exception as e:
            return False
        return data['username']

    def _retrieve_key(self):
        self.key = requests.get(self.key_url).text

app.auth_service = AuthService()


@app.before_request
def check_user():
    if not 'Authentication' in request.headers:
        abort(401)
    
    auth_header = request.headers.get('Authentication')


    try:
        username, token = auth_header.split(' ')
        username_token = app.auth_service.verify(token) 
        assert username == username_token
    except:
        abort(401)
    g.username = username

@app.post('/new')
def new_note():
    if not request.is_json:
        abort(400)

    title = request.json.get('title', False)
    body = request.json.get('body', False)

    if not title or not body:
        abort(400)
    
    if type(title) is not str or  type(body) is not str:
        abort(400)

    note_id = secrets.token_urlsafe(8)

    with get_db() as notes:
        notes[note_id] = {'title':title, 'body': body, 'author': g.username}
        author_notes = notes.get(g.username, {'notes': []})
        author_notes['notes'].append(note_id)
        notes[g.username] = author_notes
        notes.commit()
    
    return {'status': True, 'id': note_id}

@app.post('/edit/<note_id>')
def edit_note(note_id):
    if not request.is_json:
        abort(400)

    title = request.json.get('title', False)
    body = request.json.get('body', False)
    
    if type(title) is not str or type(body) is not str:
        abort(400)

    with get_db() as notes:
        note = notes.get(note_id, False)
        note['title'] = title if title else note['title']
        note['body'] = body if body else note['body']
        note['author'] = note.get('author', g.username)
        notes[note_id] = note
        notes.commit()
    
    return {'status': True, 'id': note_id}


@app.get('/list')
def list_notes():
    with get_db() as notes:
        author_notes = notes.get(g.username, {'notes': []})
    return {'status': True, 'notes': author_notes['notes']}

@app.get('/view/<note_id>')
def view_note(note_id):
    with get_db() as notes:
        note = notes.get(note_id, False)
    
    if not note:
        return jsonify({'status': False, 'err': 'Note not found'})
    
    if note['author'] != g.username:
        abort(401)

    return jsonify({'status': True, 'note': note})


@app.cli.command("install")
def install():
    
    print('Initializing db')
    with get_db() as notes:
        notes.commit()

    os.chown(DB_PATH, 1000, 1000)
    os.chown('.', 1000, 1000)
    os.chmod(DB_PATH, 0o765)

    

    
