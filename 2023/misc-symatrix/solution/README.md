# Symatrix Writeup


In the challenge we get a long C file - encoder.c, and an image, 
symatrix.png. The C code was apparently generated using Cython. 
Reversing that would be annoying, but we can find some debug comments 
inside, for example:

```
 /* "encoder.py":6
 * 
 * def hexstr_to_binstr(hexstr):
 *     n = int(hexstr, 16)             # <<<<<<<<<<<<<<
 *     bstr = ''
 *     while n > 0:
 */
```

Using a short Python script, we collected all such comments and 
concatenated them to get the original file:

```
from PIL import Image             # <<<<<<<<<<<<<<
from random import randint
import binascii
from random import randint
import binascii

def hexstr_to_binstr(hexstr):             # <<<<<<<<<<<<<<
    n = int(hexstr, 16)
    bstr = ''
    while n > 0:
        bstr = str(n % 2) + bstr
        n = n >> 1
    if len(bstr) % 8 != 0:
        bstr = '0' + bstr
    return bstr             # <<<<<<<<<<<<<<


def pixel_bit(b):             # <<<<<<<<<<<<<<
    return tuple((0, 1, b))


def embed(t1, t2):             # <<<<<<<<<<<<<<
    return tuple((t1[0] + t2[0], t1[1] + t2[1], t1[2] + t2[2]))


def full_pixel(pixel):             # <<<<<<<<<<<<<<
    return pixel[1] == 255 or pixel[2] == 255

print("Embedding file...")

bin_data = open("./flag.txt", 'rb').read()
data_to_hide = binascii.hexlify(bin_data).decode('utf-8')

base_image = Image.open("./original.png")

x_len, y_len = base_image.size
nx_len = x_len

new_image = Image.new("RGB", (nx_len, y_len))

base_matrix = base_image.load()
new_matrix = new_image.load()

binary_string = hexstr_to_binstr(data_to_hide)
remaining_bits = len(binary_string)

nx_len = nx_len - 1
next_position = 0

for i in range(0, y_len):             # <<<<<<<<<<<<<<
    for j in range(0, x_len):

        pixel = new_matrix[j, i] = base_matrix[j, i]

        if remaining_bits > 0 and next_position <= 0 and not full_pixel(pixel):             # <<<<<<<<<<<<<<
            new_matrix[nx_len - j, i] = embed(pixel_bit(int(binary_string[0])),pixel)
            next_position = randint(1, 17)
            binary_string = binary_string[1:]
            remaining_bits -= 1
        else:
            new_matrix[nx_len - j, i] = pixel
            next_position -= 1             # <<<<<<<<<<<<<<


new_image.save("./symatrix.png")
new_image.close()
base_image.close()

print("Work done!")
exit(1)             # <<<<<<<<<<<<<<
```

The encoder loads the flag from a local file, encodes it as bits, 
and then embeds those bits in some pixels. Specifically, it skips a
random number of pixels (it also skips pixels that have value 255 
in one of the channels), and then adds either (0, 1, 0) or (0, 1, 1) 
to the pixel value. The whole image is also duplicated, mirrored 
on the right half, with only the right half containing the 
modifications. We can therefore simply go over all pixels and check 
if it is equal to its mirrored counterpart; if it isn’t, we check 
whether the blue channel difference between those is one or zero 
and add that bit to the flag. Finally, we decode the bits to get 
the flag:

```
from PIL import Image             # <<<<<<<<<<<<<<

def full_pixel(pixel):             # <<<<<<<<<<<<<<
    return pixel[1] == 255 or pixel[2] == 255

image = Image.open("./symatrix.png")
matrix = image.load()

x_len, y_len = image.size
x_len //= 2
nx_len = x_len * 2 - 1
bits = ""

for i in range(0, y_len):             # <<<<<<<<<<<<<<
    for j in range(0, x_len):
        pixel = matrix[j, i]
        if not full_pixel(pixel):             # <<<<<<<<<<<<<<
            if matrix[nx_len - j, i] != pixel:
              bit = "1" if matrix[nx_len -j, i][2] != pixel[2] else "0"
              bits += bit

flag = ""
for i in range(0, len(bits), 8):
  ch = chr(int(bits[i:i+8], 2))
  flag += ch

print(flag)

λ python3 solve.py 
CTF{W4ke_Up_Ne0+Th1s_I5_Th3_Fl4g!}
```


