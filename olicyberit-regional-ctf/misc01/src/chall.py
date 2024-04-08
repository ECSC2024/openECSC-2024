#!/usr/bin/env python3

import os

flag = os.getenv('FLAG', 'flag{redacted}')

files = [
  {
    'name': 'flag.txt',
    'content': flag
  },
  {
    'name': 'Secret.txt',
    'content': 'https://www.youtube.com/watch?v=dQw4w9WgXcQ'
  },
  {
    'name': '/etc/passwd',
    'content': '''root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
user:x:1000:1000:User,,,:/home/user:/bin/bash'''
  }
]

bannedwords = ['flag', 'secret', 'password', 'key']
def cleanup(filename):
  for word in bannedwords:
    filename = filename.replace(word, '')
  return filename

def print_file_list():
  print('Files:')
  files.sort(key=lambda x: x['name'])
  for file in files:
    print(f'  - {file["name"]}')

while True:
  print_file_list()
  print()
  filename = input('Read file: ')
  filename = cleanup(filename)

  for f in files:
    if f['name'] == filename:
      print()
      print(f['content'])
      print()
      break
  else:
    filename = f'{filename.encode()}'[2:-1]
    print(f'File "{filename}" not found.')
