import os

for i in range(5):
  current = f'snap{i}'
  previous = f'snap{i-1}'

  os.system(f'touch /pool/{i}.txt')
  os.system(f'zfs snapshot pool@{current}')
  os.system(f'rm -f /pool/{i}.txt')
  
  if i == 0:
    continue
  os.system(f'zfs send -i pool@{previous} pool@{current} > snap-{previous}-to-{current}.zfs')
