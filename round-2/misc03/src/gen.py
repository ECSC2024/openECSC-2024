import os
import subprocess
import sys
import time

# docker build . -t challenge60gen

user_id = sys.argv[1]
pwd = os.getcwd()

for _ in range(20):
    p = subprocess.Popen(
        [
            'docker', 'run',
            '--restart', 'no',
            '-v', f'{pwd}/attachments/RF_48ksps_100bps.float/:/attachments',
            '--rm', '-it',
            'challenge60gen',
            user_id ,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    p.wait()

    stdout = p.stdout.read().decode()
    if '===FLAG===' in stdout:
        for _ in range(10):
            if os.path.isfile(f'{pwd}/attachments/RF_48ksps_100bps.float/{user_id}'):
                break

            time.sleep(.5)
        else:
            continue

        print(stdout.split('===FLAG===')[1])
        break
