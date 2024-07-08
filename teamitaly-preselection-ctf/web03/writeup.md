# TeamItaly Preselection CTF 2024

## [web] Past(a)man (0 solves)

Use our simple APIs to store your favourite pasta recipes.

Site: [http://pastaman.challs.external.open.ecsc2024.it](http://pastaman.challs.external.open.ecsc2024.it)

Author: Stefano Alberto <@Xato>

## Overview

The application is a simple interface users to make API requests with a curl command constructed from data entered by the user.

The user can control the path, method, headers and body of the request, and requests can only be made to the server reachable at `http://api/`.

The flag is used as an environment variable in the API server, but it's also saveed in the `docker-compose.yml` file which is copied in the docker of the exposed server executing the curl requests.

## Solution

The first step for the solution requires including the file with the flag in a request. To do this, you can use curl's special syntax to read data from a file if the supplied parameter starts with the '@' character.

This syntax is supported by both the '--data' parameter and '-H' parameter controlled by the user.
Inserting the payload `@/app/docker-compose.yml` in one of these parameters allows the contents of the file (and the flag) to be sent within the generated request.

Since we cann't control the host to which the request is made, we must find a way to read the contents of the file through the api server. This is possible using the TRACE method, supported by default by the API server, which allows a copy of the HTTP request made to be returned as a response. This method only supports requests without a body, so the file to be leaked must be placed inside the headers.

To get the flag we need to call `request.php` with the following body: `path=%2F&method=TRACE&headers%5B%5D=@/app/docker-compose.yml`

## Exploit

```py
import requests

URL = 'http://pastaman.challs.external.open.ecsc2024.it/'
r = requests.post(URL + '/request.php', data={'path': '/', 'method': 'TRACE', 'headers[]': '@/app/docker-compose.yml'})
print(r.text)
```
