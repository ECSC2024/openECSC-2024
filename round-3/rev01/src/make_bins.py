import numpy as np
import struct
import random

SIZE = 64

# make Hadamard matrix
def make_hadamard_matrix(n) -> np.ndarray:
    if n == 1:
        return np.array([1])
    else:
        submatrix = make_hadamard_matrix(n // 2)
        submatrix = np.concatenate((np.vstack((submatrix, submatrix)), np.vstack((submatrix, -submatrix))), axis=1)
        return submatrix
    
x = make_hadamard_matrix(SIZE).reshape((SIZE,SIZE))
y = (x == -1).astype(int)

ids = list(range(SIZE))
random.seed(12)
random.shuffle(ids)
for i,j in zip(ids, list(range(SIZE))):
    code = np.packbits(y[i], bitorder='little').tobytes()
    # struct pack into int64_t
    code = struct.unpack('Q', code)[0]
    print(f'./codes/{j}.bin: {code}')
    with open(f'./codes/{j}.bin', 'wb') as f:
        f.write(struct.pack('Q', code))