from pwn import *

conn = remote("127.0.0.1", 1337)

for x in range(10):
    conn.send(str(x).encode())
    size=conn.recv(1)
    print(size)
    print(int.from_bytes(size, 'little'))
    data=conn.recv(int.from_bytes(size, 'little'))
    print(disasm(data, arch="amd64"))
