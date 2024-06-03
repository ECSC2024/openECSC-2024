# CyberChallenge.IT 2024 - University CTF

## [misc] Matrioska (78 solves)

The password is `password`

Author: Giovanni Minotti <@Giotino>

## Overview

We are presented with a zip file containing another compresses/encoded file and so on. The goal is to extract the innermost file.

## Solution

First we detect the file type, I used the `file` command:

```python
def detect(filename):
  m = subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode().strip().split(': ')[1]
  if m.startswith("ASCII text"):
    file = open(filename, 'r').readline()
    if file.startswith("CCIT{"):
      return 'FLAG'
    elif file.startswith('00000000:'):
      return 'HEX'
    else:
      return 'BASE64'
  elif m.startswith("Zip archive data"):
    return 'ZIP'
  elif m.startswith("XZ compressed data"):
    return 'XZ'
  elif m.startswith("bzip2 compressed data"):
    return 'BZIP2'
  elif m.startswith("gzip compressed data"):
    return 'GZIP'
  elif m.startswith("POSIX tar archive"):
    return 'TAR'
  elif m.startswith("7-zip archive data"):
    return '7Z'
  else:
    print("Unknown file type")
    print(m)
    sys.exit(1)
```
  
Then we decode/extract the file:
(tip: `7z` is able to extract most of the compressed files)
  
```python
def extract(filename, destination):
  result = subprocess.run(["7z", "x", "-ppassword", filename, f"-o{destination}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  if result.returncode != 0:
    print(result.stderr.decode())
    sys.exit(1)

f = detect(f"{currdir.name}/{currfile}")
if f == 'FLAG':
  flag = open(f"{currdir.name}/{currfile}", 'r').readline()
  print(flag)
  sys.exit(0)
elif f == 'ZIP' or f == 'XZ' or f == 'BZIP2' or f == 'GZIP' or f == 'TAR' or f == '7Z':
  extract(f"{currdir.name}/{currfile}", destdir.name)
  currdir.cleanup()
  currfile = os.listdir(destdir.name)[0]
  currdir = destdir
elif f == 'HEX':
  os.system(f"xxd -r {currdir.name}/{currfile} > {destdir.name}/{currfile}")
  currdir.cleanup()
  currdir = destdir
elif f == 'BASE64':
  os.system(f"base64 -d {currdir.name}/{currfile} > {destdir.name}/{currfile}")
  currdir.cleanup()
  currdir = destdir
else:
  print("Unknown file type")
  sys.exit(1)
```

Repeat the process until the flag is found.

## Exploit

```python
import os, sys
import subprocess
import tempfile

def detect(filename):
  m = subprocess.run(["file", filename], stdout=subprocess.PIPE).stdout.decode().strip().split(': ')[1]
  if m.startswith("ASCII text"):
    file = open(filename, 'r').readline()
    if file.startswith("CCIT{"):
      return 'FLAG'
    elif file.startswith('00000000:'):
      return 'HEX'
    else:
      return 'BASE64'
  elif m.startswith("Zip archive data"):
    return 'ZIP'
  elif m.startswith("XZ compressed data"):
    return 'XZ'
  elif m.startswith("bzip2 compressed data"):
    return 'BZIP2'
  elif m.startswith("gzip compressed data"):
    return 'GZIP'
  elif m.startswith("POSIX tar archive"):
    return 'TAR'
  elif m.startswith("7-zip archive data"):
    return '7Z'
  else:
    print("Unknown file type")
    print(m)
    sys.exit(1)
  
def extract(filename, destination):
  result = subprocess.run(["7z", "x", "-ppassword", filename, f"-o{destination}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
  if result.returncode != 0:
    print(result.stderr.decode())
    sys.exit(1)
  
def solve(filename):
  currfile = filename
  currdir = tempfile.TemporaryDirectory()
  os.system(f"cp {filename} {currdir.name}")
  while True:
    destdir = tempfile.TemporaryDirectory()
    f = detect(f"{currdir.name}/{currfile}")
    if f == 'FLAG':
      flag = open(f"{currdir.name}/{currfile}", 'r').readline()
      return flag
    elif f == 'ZIP' or f == 'XZ' or f == 'BZIP2' or f == 'GZIP' or f == 'TAR' or f == '7Z':
      extract(f"{currdir.name}/{currfile}", destdir.name)
      currdir.cleanup()
      currfile = os.listdir(destdir.name)[0]
      currdir = destdir
    elif f == 'HEX':
      os.system(f"xxd -r {currdir.name}/{currfile} > {destdir.name}/{currfile}")
      currdir.cleanup()
      currdir = destdir
    elif f == 'BASE64':
      os.system(f"base64 -d {currdir.name}/{currfile} > {destdir.name}/{currfile}")
      currdir.cleanup()
      currdir = destdir
    else:
      print("Unknown file type")
      sys.exit(1)

if __name__ == "__main__":
  print(solve(sys.argv[1]))
```
