import os
import time

files = os.listdir('../src/snapshots')
files.sort(key=lambda f: int(f.split('-')[1]))

for file in files:
    print(file)
    time.sleep(1)
    os.system(f'sudo zfs receive pool/test < ../src/snapshots/{file}')
