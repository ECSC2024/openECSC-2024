import os
import logging
import requests
import pymongo
from uuid import UUID, uuid4
from textwrap import dedent
from datetime import datetime, timedelta
from hashlib import sha256
from flask import Flask, request, make_response
from apscheduler.schedulers.background import BackgroundScheduler
from secret import get_flag

app = Flask(__name__)
app.secret_key = os.urandom(32)
HEADLESS_HOST = os.getenv("HEADLESS_HOST")
HEADLESS_AUTH = os.getenv("HEADLESS_AUTH")
POW_BYPASS = os.getenv("POW_BYPASS")
SELF_HOST = os.getenv("SELF_HOST")
MONGO_DB = os.getenv("MONGO_DB")
MONGO_USER = os.getenv("MONGO_USER")
MONGO_PASSWORD = os.getenv("MONGO_PASSWORD")
MONGO_HOST = os.getenv("MONGO_HOST")
MONGO_PORT = os.getenv("MONGO_PORT")

gunicorn_logger = logging.getLogger('gunicorn.error')
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(logging.INFO)

client = pymongo.MongoClient(f"mongodb://{MONGO_USER}:{MONGO_PASSWORD}@{MONGO_HOST}:{MONGO_PORT}/")
db = client[MONGO_DB]
proposals = db["proposals"]
pows = db["pows"]

def clean_db():
    proposals.delete_many({"exp": {"$lte": datetime.now()}})
    pows.delete_many({"exp": {"$lte": datetime.now()}})
scheduler = BackgroundScheduler()
scheduler.add_job(clean_db, 'interval', minutes=10)
scheduler.start()

@app.get("/")
def index():
    app.logger.info(f"index:REQUEST_DATA: {request.data}")
    app.logger.info(f"index:REQUEST_HEADERS:\n{request.headers}")
    return "Yeah, i'm working fine", 418


@app.route("/forbidden")
def forbidden():
    return "Forbidden", 403


@app.get("/proposals/<string:uuid>")
def get_proposal(uuid):
    try:
        uuid = str(UUID(uuid, version=4))
    except ValueError as e:
        app.logger.error(f"get_proposal: {e}")
        return "Not found", 404

    try:
        proposal = proposals.find_one({"uuid": uuid})
        return dedent(f"""
        <html>
            <head>
                <title>{proposal["name"]}</title>
            </head>
            <body>
                TODO: implement proposal description page
            </body>
        </html>
        """)
    except KeyError:
        return "Not found", 404


@app.post("/proposals")
def post_proposal():
    app.logger.info(f"post_proposal:REQUEST_DATA: {request.data}")
    app.logger.info(f"post_proposal:REQUEST_HEADERS:\n{request.headers}")
    try:
        body = request.json
        uuid = UUID(body["uuid"], version=4) 
        name = body["name"]
        price = int(body["price"])
        description = body["description"]
        seller = body["seller"]
        exp = datetime.now() + timedelta(minutes=10)
    except Exception as e:
        app.logger.error(f"post_proposal: {e}")
        return "Unprocessable entity", 422
    proposals.insert_one({
        "uuid": str(uuid),
        "name": name,
        "price": price,
        "description": description,
        "seller": seller,
        "exp": exp,
    })

    return "Created", 201


@app.get("/moo")
def moo():
    with open("moo") as moo:
        return moo.read(), 418


@app.get("/pow")
def get_pow():
    pow = {
        "uuid": str(uuid4()),
        "pow": sha256(os.urandom(24)).hexdigest()[-5:],
        "exp": datetime.now() + timedelta(minutes=10),
    }
    
    pows.insert_one(pow)
    del pow["_id"]
    return pow


@app.post("/notify")
def notify():
    try:
        body = request.json
        uuid = str(UUID(body["proposal_uuid"], version=4))
        pow_uuid = str(UUID(body["pow_uuid"], version=4))
        pow_solution = body["pow_solution"]
    except:
        return "Unprocessable entity", 422

    if (pow := pows.find_one_and_delete({"uuid": pow_uuid})) == None:
        return "Bad pow", 403
    if pow_solution != POW_BYPASS and pow["pow"] != sha256(pow_solution.encode()).hexdigest()[-5:]:
        return "Bad pow", 403

    r = requests.post(
        f"http://{HEADLESS_HOST}",
        headers={"X-Auth": HEADLESS_AUTH},
        json={
            "actions": [
                {
                    "type": "request",
                    "url": f"http://{SELF_HOST}/",
                },
                {
                    "type": "set-cookie",
                    "name": "flag",
                    "value": get_flag()
                },
                {
                    "type": "request",
                    "url": f"http://{SELF_HOST}/proposals/{uuid}",
                },
                {
                    "type": "sleep",
                    "time": 5,
                },
            ],
            "timeout": 30,
        })
    if r.status_code != 200:
        return "Failed contacting headless", 500

    return "Success", 200
