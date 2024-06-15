from flask import Flask, request, session, redirect, render_template, flash
from pymongo import MongoClient
import os
from hashcash import hashcash_check
import json
import base64
import requests
from secret import get_flag
from urllib.parse import urlencode
from bson.objectid import ObjectId

app = Flask(__name__)
# secret key for session
app.secret_key = 'c8dada0ffc4dcf6021ed00d34933e2e0e827368e3df8b05381d88fa060285d37'

MONGO_HOST = os.getenv('MONGO_HOST', 'localhost')
MONGO_USER = os.getenv('MONGO_USER', 'user')
MONGO_PASS = os.getenv('MONGO_PASS', 'password')

HEADLESS_HOST = os.getenv('HEADLESS_HOST')
HEADLESS_AUTH = os.getenv('HEADLESS_AUTH')
WEB_DOM = os.getenv('WEB_DOM')
CHECKER_TOKEN = os.getenv('CHECKER_TOKEN')

mongo_client = MongoClient(
    f'mongodb://{MONGO_USER}:{MONGO_PASS}@{MONGO_HOST}:27017/')

db = mongo_client['shop']


@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')


@app.route('/', methods=['GET'])
def index():
    if not session.get('user_id'):
        return redirect('/signup')

    # get hashcash pow resource from db
    pow_resource = db['users'].find_one({
        '_id': ObjectId(session['user_id'])
    })['pow']

    products = db['products'].find()

    return render_template('index.html', products=products, pow_resource=pow_resource)


@app.route('/dashboard', methods=['GET'])
def dashboard():
    if not session.get('user_id'):
        return redirect('/signup')

    orders = db['orders'].find({'affiliation': {'$eq': session['user_id']}})

    return render_template('dashboard.html', orders=orders)


@app.route('/cart', methods=['GET'])
def cart():
    if not session.get('user_id'):
        return redirect('/signup')

    # get hashcash pow resource from db
    pow_resource = db['users'].find_one({
        '_id': ObjectId(session['user_id'])
    })['pow']

    return render_template('cart.html', pow_resource=pow_resource)


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    if not data:
        return 'invalid data', 400

    if not data.get('username') or not isinstance(data['username'], str):
        return 'invalid data', 400

    # generate hashcash pow resource
    pow_resource = os.urandom(8).hex()
    user = db['users'].insert_one({
        'username': data['username'],
        'pow': pow_resource
    })

    session['user'] = data['username']
    session['user_id'] = str(user.inserted_id)

    return {'status': 'ok'}


@app.route('/api/order', methods=['POST'])
def order():
    data = request.json
    if not data:
        return 'invalid data', 400

    if not data.get('cart') or not isinstance(data['cart'], list):
        flash('Cannot place order: cart is empty', 'danger')
        return 'invalid data', 400

    if data.get('affiliation') and not isinstance(data['affiliation'], str):
        flash('Cannot place order: invalid affiliation', 'danger')
        return 'invalid data', 400

    if data.get('message') and not isinstance(data['message'], str):
        flash('Cannot place order: invalid affiliation', 'danger')
        return 'invalid data', 400

    db['orders'].insert_one({
        'cart': data['cart'],
        'affiliation': data['affiliation'],
        'message': data['message'],
        'user': session['user_id'],
    })

    flash('Order placed successfully', 'success')

    return {'status': 'ok'}


@app.route('/api/feedback', methods=['POST'])
def feedback():
    if not session.get('user_id'):
        return 'invalid data', 400

    # get hashcash pow resource from db
    pow_resource = db['users'].find_one({
        '_id': ObjectId(session['user_id'])
    })['pow']

    data = request.json
    if not data:
        return 'invalid data', 400

    if not data.get('cart') or not isinstance(data['cart'], list):
        flash('Invalid cart', 'danger')
        return 'invalid data', 400

    if not data.get('pow') or not isinstance(data['pow'], str):
        flash('Invalid proof of work', 'danger')
        return 'invalid data', 400

    try:
        if data['pow'] != CHECKER_TOKEN and not hashcash_check(data['pow'].strip(), pow_resource, 26):
            raise Exception('Wrong pow')
    except Exception as _:
        flash('Invalid proof of work', 'danger')
        return 'invalid data', 400

    # update hashcash pow resource
    db['users'].update_one({
        '_id': ObjectId(session['user_id'])
    }, {
        '$set': {'pow': os.urandom(8).hex()}
    })

    try:
        res = requests.post(f'http://{HEADLESS_HOST}', json={
            'actions': [
                {
                    'type': 'request',
                    'url': f'http://{WEB_DOM}/signup'
                },
                {
                    'type': 'sleep',
                    'time': 1
                },
                {
                    'type': 'type',
                    'element': '#username',
                    'value': 'admin'
                },
                {
                    'type': 'click',
                    'element': '#submit',
                },
                {
                    'type': 'sleep',
                    'time': 1
                },
                {
                    'type': 'request',
                    'url': f'http://{WEB_DOM}/cart?{urlencode({"cart": base64.b64encode(json.dumps(data["cart"]).encode()).decode()})}'
                },
                {
                    'type': 'sleep',
                    'time': 3
                },
                {
                    'type': 'type',
                    'element': '#customMessage',
                    'value': get_flag()
                },
                {
                    'type': 'click',
                    'element': '#placeOrderBtn',
                },
                {
                    'type': 'sleep',
                    'time': 3
                },
            ]
        }, headers={
            'X-Auth': HEADLESS_AUTH
        })

        if res.status_code == 200:
            flash('The admin will visit your cart', 'success')
        else:
            flash('There was an error while contacting the headless browser', 'danger')
    except Exception as _:
        flash('There was an error while contacting the headless browser', 'danger')

    return {'status': 'ok'}


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
