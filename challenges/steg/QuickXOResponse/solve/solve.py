#!/usr/bin/env python
from PIL import Image

# Load images and convert to mode '1' (1-bit pixels, black and white)
img1 = Image.open("key.png").convert("1")
img2 = Image.open("fake.png").convert("1")

# Ensure dimensions match
assert img1.size == img2.size == (75, 75), "Images must be 75x75 pixels"

# Create a new blank 1-bit image for the result
result_img = Image.new("1", img1.size)

# XOR each pixel (0 or 255)
for x in range(75):
    for y in range(75):
        p1 = img1.getpixel((x, y)) // 255  # Convert to 0 or 1
        p2 = img2.getpixel((x, y)) // 255
        result_pixel = (p1 ^ p2) * 255     # Back to 0 or 255
        result_img.putpixel((x, y), result_pixel)

# Save the resulting XOR image
result_img.save("flag.png")
print("Saved 1-bit XOR image as flag.png")
