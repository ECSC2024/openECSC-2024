# openECSC 2024 - Round 2

## [misc] Revenge of the Blind maze (369 solves)

Welcome back to the blind maze, this time you'll have a harder time finding the flag, good luck.

Site: [http://blindmazerevenge.challs.open.ecsc2024.it](http://blindmazerevenge.challs.open.ecsc2024.it)

Author: Giovanni Minotti <@giotino>

## Solution

The website implements a simple maze game, and the user has to perform all the correct moves to exit the maze and find the flag. The PCAP attachment contains all the moves from a previous winner. There are some move that `FAILED`, so we have to ignore them.  
We can extract them with `pyshark` ignoring the failed ones. After that we can use the moves to navigate the maze and get the flag.

The first move is going to be `start`, it creates our session and then we can use the moves to navigate the maze. Since we are assigned a session to track our position we need to use a `requests.Session()` to store the cookies.


```python
import pyshark

cap = pyshark.FileCapture("./capture.pcap", display_filter="http")

moves = []

for pkt in cap:
    if hasattr(pkt.http, "request_method"):
        # Get move
        moves.append(pkt.http.request_uri_query.split("=")[1])
    if hasattr(pkt.http, "response"):
        # Remove move if failed
        if "FAILED" in pkt.http.file_data:
            moves.pop()
```

Then we can use all the recorded moves to navigate the maze, repeating the move when it fails.

```python
import requests

ENDPOINT = "http://blindmaze.challs.open.ecsc2024.it/maze"

s = requests.Session()

i = 0
while i < len(moves):
    move = moves[i]
    print('Move:', move)
    r = s.get(ENDPOINT, params={"direction": move})
    if "FAILED" not in r.text:
        i += 1
    else:
        print('Failed, retrying...')

print(r.text)
```
