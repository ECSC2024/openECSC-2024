# OliCyber.IT 2024 - National Final

## [misc] Kinda diffusion (27 solves)

In AI, diffusion models add noise to the image and then remove it.
I added the noise, you remove it!

Author: Aleandro Prudenzano <@drw0if>

## Overview
The image is processed by adding a random number in the range [0,255] to each pixel.

## Solution
The seed of the random generator is also randomly generated in the range [0,255], so we can brute-force all the seeds by running the algorithm in reverse. To speed up the process, we can use `multiprocessing` to "decrypt" multiple images at the same time; in the end, only one image will make sense and contain the flag.

## Exploit
```python
from PIL import Image
import random
from multiprocessing import Pool as ThreadPool
import sys

def denoise(x):
    image, seed = x
    random.seed(seed)

    for x in range(image.width):
        for y in range(image.height):
            p = image.getpixel((x,y))
            p = tuple([(c - random.randint(0, 255))%256 for c in p])
            image.putpixel((x,y), p)

    print(f"Done with {seed}")
    image.save(f"output/flag-{seed}.png")

def main(filepath):
    img = Image.open(filepath)

    p = ThreadPool(16)
    p.map_async(denoise, [(img.copy(), s) for s in range(256)]).get(0xffff)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <image>")
        sys.exit(1)
    
    main(sys.argv[1])
```
