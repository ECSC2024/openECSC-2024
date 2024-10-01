import os
import glob
import hashlib
import logging
from datetime import datetime, timezone, timedelta

from pymongo import MongoClient
from flask import Flask, request, make_response
from flask_cors import CORS
from apscheduler.schedulers.background import BackgroundScheduler

from models import (
    forbidden_ids,
    FileMetadata,
)
from marketing import files

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
metadata = db.metadata


def initialize_db():
    for f in files:
        m = f["metadata"]
        fm = FileMetadata(
            m["author"],
            m["filename"],
            m["description"],
            id = m["id"],
        )
        if not metadata.find_one({"id": m["id"]}):
            fm.write(metadata, f["content"])


def cleanup():
    app.logger.info("Cleaning mongodb...")
    threshold = datetime.now(tz=timezone.utc) - timedelta(hours=4)
    metadata.delete_many({"creation_time": {"$lt": threshold}, "init": False})
    for f in glob.glob("/tmp/*"):
        os.remove(f)
    app.logger.info("Cleaning complete!")


scheduler = BackgroundScheduler()
cleaning_job = scheduler.add_job(cleanup, 'interval', hours=2)
scheduler.start()

metadata.delete_many({})
initialize_db()


@app.get("/files")
def get_files():
    return [f["metadata"] for f in files]


@app.get("/files/<id>")
def get_file(id):
    if id == "ea41c85c-3db0-4ded-aff1-a93994f64d81":
        return "", 403
    res = metadata.find_one({
        "id": {"$eq": id}
    })
    if res is None:
        return "", 404
    m = FileMetadata(
        res["author"],
        res["filename"],
        res["description"],
        id=res["id"],
    )
    if files[-1]["metadata"]["filename"] in res["filename"]:
        return "", 403
    #return m.read(int(request.args.get("offset", 0)))
    return m.read(int(request.args.get("offset", 0)), request.remote_addr)


def parse_file(body, id=None):
    import re, string
    CONTENT_CHECK = re.compile(f"[^ {string.ascii_letters}]")

    if CONTENT_CHECK.search(body["content"]):
        raise ValueError()
    if len(body["content"]) > 200:
        raise ValueError()

    return {
        "metadata": FileMetadata(
            body["author"],
            body["filename"],
            body["description"],
            id,
        ),
        "content": body["content"]
    }


@app.post("/files")
def post_file():
    body = request.json
    try:
        parsed_body = parse_file(body)
    except (KeyError, ValueError):
        return "", 422
    m = parsed_body["metadata"]
    content = parsed_body["content"]
    m.write(metadata, content)
    r = make_response("", 201)
    r.headers["Location"] = f"/api/v1/files/{m.id}"
    return r


@app.put("/files/<id>")
def put_file(id):
    if id in forbidden_ids:
        return "", 403
    body = request.json
    try:
        parsed_body = parse_file(body, id)
    except (KeyError, ValueError):
        return "", 422
    m = parsed_body["metadata"]
    content = parsed_body["content"]
    m.write(metadata, content)
    r = make_response("", 201)
    r.headers["Location"] = f"/api/v1/files/{m.id}"
    return r


@app.get("/files/<id>/checksum")
def get_file_integrity(id):
    if id == "ea41c85c-3db0-4ded-aff1-a93994f64d81":
        return "", 403
    res = metadata.find_one({
        "id": {"$eq": id}
    })
    if res is None:
        return "", 404
    m = FileMetadata(
        res["author"],
        res["filename"],
        res["description"],
        id=res["id"],
    )
    #content = m.read(int(request.args.get("offset", 0)))
    content = m.read(int(request.args.get("offset", 0)), request.remote_addr)
    return {"checksum": hashlib.md5(content.encode()).hexdigest()}