import numpy as np
import matplotlib.pyplot as plt
import sys

dec = bytes.fromhex(sys.argv[1])

img = np.array([[x >> 4, x & 0xF] for x in dec], dtype=np.uint8).flatten().reshape(64,128)

plt.imshow(img, cmap='gray')
plt.show()
