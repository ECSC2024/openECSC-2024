#!/bin/python3
import os
import string
import shutil
import subprocess as sp

base_certificate_directory="/tmp"
root_certificate="/rootcerts/rootCACert.pem"
root_certificate_key="./rootcerts/rootCAKey.pem"

print("Hello employee, welcome to FlagsDistribution certificate signing service!")
subject=input("Please provide your name: ")
subject=subject.strip()
if(len(subject) == 0):
    print("Please provide your name.")
    exit(-1)
if(not all([_ in string.ascii_letters+string.digits for _ in subject])):
    print("Sorry, we don't accept special characters in subject field.")
    exit(-1)
if("FlagsDistributionAdministrator" in subject):
    print("Sorry, administrators must physically show up at the IT desk to verify their identity.")
    exit(-1)

shutil.rmtree(f"{base_certificate_directory}/{subject}", ignore_errors=True)
os.mkdir(f"{base_certificate_directory}/{subject}")
child = sp.Popen(["openssl", "genrsa", "-out", f"{base_certificate_directory}/{subject}/{subject}.key", "2048"], stdout=sp.PIPE)
streamdata = child.communicate()[0]
rc = child.returncode
if(rc!=0):
    print("Something went wrong while generating your key.")
    exit(-1)

child = sp.Popen(["openssl", "req", "-new", "-out", f"{base_certificate_directory}/{subject}/{subject}.csr", "-key", f"{base_certificate_directory}/{subject}/{subject}.key", "-subj", f"/C=IT/CN={subject}"], stdout=sp.PIPE)
streamdata = child.communicate()[0]
rc = child.returncode
if(rc!=0):
    print("Something went wrong while generating your certificate signing request.")
    exit(-1)

with open(f"{base_certificate_directory}/{subject}/{subject}.cnf", "w") as f:
    f.write('''basicConstraints = CA:FALSE
nsCertType = client, email
nsComment = ""
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
keyUsage = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, emailProtection''')

child = sp.Popen(["openssl", "x509", "-req", "-in", f"{base_certificate_directory}/{subject}/{subject}.csr", "-CA", f"{root_certificate}", "-CAkey", f"{root_certificate_key}", "-out", f"{base_certificate_directory}/{subject}/{subject}.pem", "-CAcreateserial", "-days", "365", "-sha256", "-extfile", f"{base_certificate_directory}/{subject}/{subject}.cnf"], stdout=sp.PIPE)
streamdata = child.communicate()[0]
rc = child.returncode
if(rc!=0):
    print("Something went wrong while signing your certificate.")
    exit(-1)

print("Here is your certificate:")
with open(f"{base_certificate_directory}/{subject}/{subject}.pem", "r") as f:
    for line in f.readlines():
        print(line.strip())

print("Here is your certificate key:")
with open(f"{base_certificate_directory}/{subject}/{subject}.key", "r") as f:
    for line in f.readlines():
        print(line.strip())

shutil.rmtree(f"{base_certificate_directory}/{subject}", ignore_errors=True)