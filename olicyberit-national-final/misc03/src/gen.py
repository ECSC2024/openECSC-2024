import sys

AVAILABLE_IDS = list(range(1, 50 + 1))

# these don't work
for i in [12, 27, 31, 35, 39]:
    AVAILABLE_IDS.remove(i)


def read(user_id: int) -> tuple[bytes, str]:
    with open(f'src/dumps/dump{user_id}.pcapng', 'rb') as f:
        data = f.read()

    with open(f'src/flags/flag{user_id}.txt', 'r') as f:
        flag = f.read().strip()

    return data, flag


def main(user_id: int):
    data, flag = read(AVAILABLE_IDS[user_id % len(AVAILABLE_IDS)])
    with open(f'attachments/dump.pcapng/{user_id}', 'wb') as f:
        f.write(data)

    print(flag)


if __name__ == '__main__':
    main(int(sys.argv[1]))
