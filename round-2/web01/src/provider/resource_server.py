import logging
import os
from flask import (
    Blueprint,
    current_app,
    request,
    make_response
)
from functools import wraps
from textwrap import dedent
from pwhtmltopdf import HtmlToPdf
from uuid import uuid4
from tempfile import TemporaryDirectory
from pathlib import Path
import requests


resource_server_endpoints = Blueprint(
    'resource_server',
    __name__,
    url_prefix='/api/v1'
)
logger = logging.getLogger(__name__)
creds = None


def required_scope(scope):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            with current_app.app_context():
                authorization = request.headers.get("Authorization", None)
                request_token = authorization.split(" ")[-1] # Not really the right way, but for a challenge is ok i guess
                logger.info(f"RECEIVED TOKEN: {request_token}")
                try:
                    stored_token = current_app.provider.authz_state.access_tokens[request_token]
                    logger.info(f"STORED TOKEN: {stored_token}")
                    stored_scope = set(stored_token["scope"].split(" "))
                    total_scope = scope.union(set(stored_scope))
                    if len(total_scope) != len(stored_scope):
                        raise ValueError(f"Missing required scope {scope.difference(stored_scope)}")
                except (KeyError, ValueError) as e:
                    logging.info(f"Error while authorizing: {e}")
                    return {}, 401
                return current_app.ensure_sync(f)(*args, **kwargs)
        return wrapper
    return decorator


@resource_server_endpoints.get('/laundry')
@required_scope({"laundry"})
def get_laundries():
    return [
        {
            "id": "ad80d726-f160-44e0-b715-4836f53043b0",
            "name": "Small one",
            "description": "you can only wash a scarf here",
            "price": "¢25 / 15m"
        },
        {
            "id": "413758ab-15ff-4e27-9190-cd8cdf27e173",
            "name": "Medium one",
            "description": "Here you can even wash your coat",
            "price": "$1 / 15m"
        },
        {
            "id": "65f97b5c-fc87-47e1-bd57-8c7d1de1803a",
            "name": "Large one",
            "description": "Yay, here you can wash all of your clothes, and also your chihuahua",
            "price": "$5 / 15m"
        },
        {
            "id": "f5138c9e-d2da-41f1-a925-281931ffb021",
            "name": "Gargantuan one",
            "description": "Wow, the biggest one, with this beautiful toy you can even wash yourself",
            "price": "$10 / 15m"
        }
    ]


@resource_server_endpoints.get('/amenities')
@required_scope({"amenities"})
def get_amenities():
    return [
        {
            "id": "a90850b3-ecae-454e-a175-938796c4e808",
            "name": "Vending machine",
            "description": "Here you can find our vending machine, a lot of tasty things... at a reasonable price",
            "price": "See on the machine"
        },
        {
            "id": "1517a644-80ad-449e-bed7-9480f2c7b0e3",
            "name": "Table football",
            "description": "C'mon, challenge your friends in the famous calcio balilla while your clothes are being washed! show them who is the biliardino king",
            "price": "¢25 / match"
        }
    ]


@resource_server_endpoints.get("/admin")
@required_scope({"admin"})
def get_admin_endpoints():
    return {"admin_endpoints": [
        {
            "path": "/generate_report",
            "methods": ("POST",),
            "exampleBody": {"requiredBy": "John Doe"},
        },
    ]}


@resource_server_endpoints.post("/generate-report")
@required_scope({"admin"})
async def generate_report():
    body = request.json
    required_by = body.get("requiredBy", "anonymous")

    document = dedent(f"""
    <html>
        <head>
            <title>Report</title>
        </head>
        <body style="font-family: monospace;">
            <h1>Report required by: {required_by}</h1>
            <div> Income: a lot! </div>
            <div> Total earnings: $1000000000000000 </div>
            <div> Customers scammed: 10000 </div>
        </body>
    </html>
    """.strip())

    async with HtmlToPdf() as htp:
        with TemporaryDirectory() as td:
            path = Path(td)/str(uuid4())
            await htp.from_string(document, path)
            with open(path, "rb") as f:
                pdf = f.read()

    response = make_response(pdf)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = f"inline; filename={os.urandom(5).hex()}.pdf"
    return response


@resource_server_endpoints.get("/creds")
def get_creds():
    global creds
    if creds is None:
        response = requests.post(
            f"http://localhost/openid/registration",
            json={
                "response_types": [
                    "token id_token",
                    "code"
                ],
                "redirect_uris": [
                    "http://localhost:5173/"
                ]
            },
            headers={
                "Host": os.getenv('BACKEND_DOMAIN')
            }
        )

        creds = {
            "client_id": response.json()["client_id"],
            "client_secret": response.json()["client_secret"]
        }
    return creds