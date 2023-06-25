# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from PIL import Image
from random import randint
import binascii

def hexstr_to_binstr(hexstr):
    n = int(hexstr, 16)
    bstr = ''
    while n > 0:
        bstr = str(n % 2) + bstr
        n = n >> 1
    if len(bstr) % 8 != 0:
        bstr = '0' + bstr
    return bstr


def pixel_bit(b):
    return tuple((0, 1, b))


def embed(t1, t2):
    return tuple((t1[0] + t2[0], t1[1] + t2[1], t1[2] + t2[2]))


def full_pixel(pixel):
    return pixel[1] == 255 or pixel[2] == 255

print("Embedding file...")

bin_data = open("./flag.txt", 'rb').read()
data_to_hide = binascii.hexlify(bin_data).decode('utf-8')

base_image = Image.open("./original.png")

x_len, y_len = base_image.size
nx_len = x_len * 2

new_image = Image.new("RGB", (nx_len, y_len))

base_matrix = base_image.load()
new_matrix = new_image.load()

binary_string = hexstr_to_binstr(data_to_hide)
remaining_bits = len(binary_string)

nx_len = nx_len - 1
next_position = 0

for i in range(0, y_len):
    for j in range(0, x_len):

        pixel = new_matrix[j, i] = base_matrix[j, i]

        if remaining_bits > 0 and next_position <= 0 and not full_pixel(pixel):
            new_matrix[nx_len - j, i] = embed(pixel_bit(int(binary_string[0])),pixel)
            next_position = randint(1, 17)
            binary_string = binary_string[1:]
            remaining_bits -= 1
        else:
            new_matrix[nx_len - j, i] = pixel
            next_position -= 1


new_image.save("./symatrix.png")
new_image.close()
base_image.close()

print("Work done!")
exit(1)
