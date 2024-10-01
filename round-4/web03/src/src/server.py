import http.server
import socketserver
import urllib.parse
import markdown2
import logging
import uuid
import os
import requests
from socketserver import ThreadingMixIn

# Configure logging
logging.basicConfig(level=logging.INFO)

# Load configuration from environment variables or use default
PORT = int(os.getenv("PORT", "8000"))
DATA_DIR = os.getenv("DATA_DIR", "./data")

FLAG = os.getenv("FLAG", "flag{this_is_a_fake_flag}")
BOT_HOST = os.getenv("HEADLESS_HOST", "headless:5000")
BOT_SECRET = os.getenv("HEADLESS_AUTH", "supersecret")
CHALL_HOST = os.getenv("CHALL_HOST", "http://simplemdserver.challs.open.ecsc2024.it:8000/")

if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)


class MyHandler(http.server.BaseHTTPRequestHandler):

    def static_page(self, page):
        with open(f"./pages/header.html", "r") as header:
            with open(f"./pages/{page}.html", "r") as f:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(header.read(), "utf-8"))
                self.wfile.write(bytes(f.read(), "utf-8"))

    def get_document(self):
        query = urllib.parse.urlparse(self.path).query
        id = urllib.parse.parse_qs(query).get("id", [""])[0]

        if not id:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(bytes("<h1>Bad Request</h1>", "utf-8"))
            return

        try:
            with open(os.path.join(DATA_DIR, os.path.basename(id)), "r") as f:
                data = f.read()
                self.send_response(200)
                self.end_headers()
                self.wfile.write(bytes(data, "utf-8"))
                return

        except FileNotFoundError:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(bytes("<h1>Not Found</h1>", "utf-8"))

    def markdown(self):
        query = urllib.parse.urlparse(self.path).query
        data = urllib.parse.parse_qs(query).get("x", [""])[0]

        # Convert markdown to HTML
        data = markdown2.markdown(data, safe_mode="escape")

        # Send response
        self.send_response(200)
        self.end_headers()
        self.wfile.write(bytes(f"{data}", "utf-8"))

    def do_GET(self):
        try:
            url = urllib.parse.urlparse(self.path)

            # Some kind of routing
            if url.path == "/":
                return self.static_page("index")
            elif url.path in ["/list", "/new", "/report"]:
                return self.static_page(url.path[1:])
            elif url.path == "/preview":
                return self.markdown()
            elif url.path == "/get":
                return self.get_document()
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(bytes("<h1>Not Found</h1>", "utf-8"))

        except Exception as e:
            logging.error(f"Error processing request: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(bytes("<h1>Internal Server Error</h1>", "utf-8"))

    def do_POST(self):
        try:
            url = urllib.parse.urlparse(self.path)
            length = int(self.headers.get("content-length", 0))
            data = self.rfile.read(length).decode("utf-8")

            if url.path == "/new":
                id = str(uuid.uuid4())

                md = markdown2.markdown(data, safe_mode="escape")

                with open(f"{DATA_DIR}/{id}", "w") as f:
                    f.write(md)

                self.send_response(200)
                self.end_headers()
                return self.wfile.write(bytes(f"{id}", "utf-8"))

            if url.path == "/report":
                visit_url = data

                if not visit_url or not visit_url.startswith(CHALL_HOST):
                    self.send_response(400)
                    self.end_headers()
                    return self.wfile.write(b"Missing or bad URL")

                try:
                    r = requests.post(
                        'http://' + BOT_HOST,
                        headers={"X-Auth": BOT_SECRET},
                        json={
                            "actions": [
                                {
                                    "type": "request",
                                    "url": CHALL_HOST,
                                },
                                {
                                    "type": "set-cookie",
                                    "name": "flag",
                                    "value": FLAG,
                                },
                                {
                                    "type": "request",
                                    "url": visit_url,
                                },
                            ]
                        },
                    )

                except requests.exceptions.RequestException as e:
                    logging.error(f"Failed to submit: {e}")
                    self.send_response(500)
                    self.end_headers()
                    return self.wfile.write(bytes("Headless is not reachable, contact an admin", "utf-8"))

                if r.status_code != 200:
                    self.send_response(500)
                    self.end_headers()
                    return self.wfile.write(bytes("Headless error, please contact an admin", "utf-8"))

                j = r.json()

                self.send_response(200)
                self.end_headers()
                return self.wfile.write(bytes(j['job'], "utf-8"))

            if url.path == "/check_report":

                job_id = data

                if not job_id:
                    self.send_response(400)
                    self.end_headers()
                    return self.wfile.write(b"Missing job ID")

                try:
                    uuid.UUID(job_id)
                except ValueError:
                    self.send_response(400)
                    self.end_headers()
                    return self.wfile.write(b"Invalid job ID")

                try:
                    r = requests.get(f"http://{BOT_HOST}/jobs/{job_id}", headers={"X-Auth": BOT_SECRET})
                except requests.exceptions.RequestException as e:
                    logging.error(f"Failed to submit: {e}")
                    self.send_response(500)
                    self.end_headers()
                    return self.wfile.write(bytes("Headless is not reachable, contact an admin", "utf-8"))

                if r.status_code != 200:
                    logging.error(f"Failed to submit: {r.text}")
                    self.send_response(500)
                    self.end_headers()
                    return self.wfile.write(bytes("Headless error, please contact an admin", "utf-8"))

                j = r.json()

                self.send_response(200)
                self.end_headers()
                return self.wfile.write(bytes(j['status'], "utf-8"))


            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(bytes("<h1>Not Found</h1>", "utf-8"))

        except Exception as e:
            logging.error(f"Error processing request: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(bytes("<h1>Internal Server Error</h1>", "utf-8"))


class ThreadedTCPServer(ThreadingMixIn, socketserver.TCPServer):
    """Handle requests in a separate thread."""

    allow_reuse_address = True


with ThreadedTCPServer(("", PORT), MyHandler) as httpd:
    logging.info(f"Serving at port {PORT}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
