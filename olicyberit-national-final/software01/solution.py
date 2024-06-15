from pwn import *

chall = ELF("./chall")

encrypted_key=chall.read(chall.symbols["encrypted_key"], 36).decode()
encrypted_flag=chall.read(chall.symbols["flag"], 36)

holes=[[0,1],[1,1],[1,3],[3,1],[3,3],[4,5],[5,0],[5,2],[5,3]] # Obtained from the binary

def grille_encrypt(data):
    matrix=[[0,0,0,0,0,0],[0,0,0,0,0,0],[0,0,0,0,0,0],[0,0,0,0,0,0],[0,0,0,0,0,0],[0,0,0,0,0,0]]
    ctr=0
    for x in range(4):
        for y in range(9):
            matrix[holes[y][0]][holes[y][1]]=data[ctr]
            ctr+=1
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
        matrix = [[matrix[j][i] for j in range(len(matrix))] for i in range(len(matrix[0])-1,-1,-1)]
    return "".join(["".join(x) for x in matrix])

chiave = grille_encrypt(encrypted_key)
print(xor(encrypted_flag, chiave.encode()).decode())