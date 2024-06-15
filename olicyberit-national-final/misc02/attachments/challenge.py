from PIL import Image, ImageDraw, ImageFont
import os
import random
import sys

SEED = random.randint(0, 255)
FLAG = os.environ.get("FLAG", 'flag{placeholder}')

# Images not attached
def get_image():
    images = os.listdir("images")
    image = random.choice(images)
    image = Image.open(f'images/{image}')
    return image


def add_noise(image):
    for x in range(image.width):
        for y in range(image.height):
            p = image.getpixel((x,y))
            p = tuple([(c + random.randint(0, 255))%256 for c in p])
            image.putpixel((x,y), p)


def main(output_filename):
    global SEED, FLAG

    img = get_image()
    random.seed(SEED)

    SEGMENT_SIZE=16
    flag_segments = [FLAG[i:i+SEGMENT_SIZE] for i in range(0, len(FLAG), SEGMENT_SIZE)]

    FONT_SIZE=75
    START_X = 50
    START_Y = 325

    # Font not attached
    font = ImageFont.truetype("font.ttf", size=FONT_SIZE)
    I1 = ImageDraw.Draw(img)
    for i, segment in enumerate(flag_segments):
        I1.text((START_X, START_Y + i*(FONT_SIZE+100)), segment, fill="red", stroke_width=1, font=font)

    add_noise(img)

    img.save(output_filename)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 challenge.py <output_filename>")
        sys.exit(1)

    filename = sys.argv[1]
    if not filename.endswith(".png"):
        filename += ".png"

    main(filename)