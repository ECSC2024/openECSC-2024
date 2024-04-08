# OliCyber.IT 2024 - Regional CTF

## [misc] Easy login (92 solves)

We managed to intercept a user logging into a website, try to find the flag.

Website: [http://easylogin.challs.external.open.ecsc2024.it](http://easylogin.challs.external.open.ecsc2024.it)

Author: Giovanni Minotti <@Giotino>

## Solution

By analyzing the PCAP traffic (for example with Wireshark), it is easy to find the fields `username` and `password` used for login. The `TOTP` field, though, is expired and cannot be forged because the user doesn't have its secret. The PCAP also contains the `session` cookie that's still valid and can be used to login.
