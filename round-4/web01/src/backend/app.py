import logging
import random
import os
from uuid import uuid1
from functools import wraps
from datetime import datetime, timezone, timedelta

import jwt
from jwt.exceptions import InvalidTokenError
from pymongo import MongoClient
from flask import Flask, request, url_for, make_response
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler

from flag import flag
from models import Key, Post


PRODUCTS = [
    "ADDOBBO FOTONEGOZIO",
    "PICCOLOSOFT PAROLA",
    "PICCOLOSOFT PUBBLICATORE",
    "MISCELATORE",
    "MALWARE TERMINATOR",
    "PICCOLOSOFT FINESTRE 13",
    "SQUALOSURFISTA",
]

logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
app.secret_key = os.urandom(32)
CORS(app)

mongodb_username = os.getenv("MONGODB_USERNAME")
mongodb_password = os.getenv("MONGODB_PASSWORD")
mongodb_host = os.getenv("MONGODB_HOST")
mongodb_port = int(os.getenv("MONGODB_PORT"))
mongodb_uri = f"mongodb://{mongodb_username}:{mongodb_password}@{mongodb_host}"

client = MongoClient(
    host=mongodb_uri,
    port=mongodb_port,
)
db = client.db
posts = db.posts
keys = db.keys


def session_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        with app.app_context():
            try:
                session_id = request.cookies["session_id"]
                session_jwt = request.cookies["session_jwt"]
                skey = keys.find_one({"id": session_id})["key"]
                jwt_body = jwt.decode(session_jwt, skey, algorithms=["HS256"])
            except (KeyError, TypeError, InvalidTokenError) as e:
                app.logger.warn(f"Unauthorized access: {e}")
                return "", 401
        return f(session_jwt, jwt_body, *args, **kwargs)
    return wrapper


def mongodb_cleanup():
    app.logger.info("Cleaning mongodb...")
    threshold = datetime.now(tz=timezone.utc) - timedelta(hours=4)
    posts.delete_many({"creation_time": {"$lt": threshold}})
    keys.delete_many({"creation_time": {"$lt": threshold}})
    app.logger.info("Cleaning complete!")


def generate_post():
    app.logger.info("Generating random post...")
    pid = uuid1()
    posts.insert_one(vars(Post(
        str(pid),
        "*",
        "product key",
        f"Here's your new product key for {random.choice(PRODUCTS)}: {os.urandom(12).hex()}"
    )))
    app.logger.info(f"Post generated with uuid {pid}")


scheduler = BackgroundScheduler()
cleaning_job = scheduler.add_job(mongodb_cleanup, 'interval', hours=2)
posts_job = scheduler.add_job(generate_post, 'interval', minutes=30)
scheduler.start()


@app.post("/session")
def create_session():
    body = request.json
    if body["username"] != "quokka" or body["password"] != "quokka":
        return "", 401

    pid, skey = (uuid1() for _ in range(2))
    sid = os.urandom(24).hex()
    app.logger.info(f"NEW SESSION: PID={pid}, SKEY={skey}")

    jwt_body = {
        "user": "quokka",
        "propic": url_for("static", filename="propic.png"),
    }
    encoded_jwt = jwt.encode(jwt_body, skey.bytes, algorithm="HS256")

    keys.insert_one(vars(Key(
        sid,
        skey.bytes,
    )))
    posts.insert_one(vars(Post(
        str(pid),
        encoded_jwt,
        "new login",
        f"user quokka logged in at {datetime.now()}"
    )))

    response = make_response()
    response.set_cookie("session_jwt", encoded_jwt, httponly=False)
    response.set_cookie("session_id", sid, httponly=False)

    return response


@app.get("/session")
@session_required
def get_session(_, jwt_body):
    return jwt_body


@app.get("/posts")
@session_required
def get_posts(session_jwt, _):
    post_list = list(posts.find({"$or": [{"recipient": session_jwt}, {"recipient": "*"}]}))
    app.logger.info(f"POST LIST: {post_list}")
    return [{
        "id": p["id"],
        "title": p["title"],
        "text": p["text"],
    } for p in post_list]


@app.get("/superkey")
@session_required
def get_superkey(_, jwt_body):
    if jwt_body.get("user", "quokka") != "admin":
        return "", 401
    return {"msg": f"Here's my super secret key: {flag()}"}