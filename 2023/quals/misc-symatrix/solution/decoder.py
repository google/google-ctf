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
import os

image = Image.open("./symatrix.png")
image_matrix = image.load()

x_len, y_len = image.size

if x_len % 2 != 0:
    print("Error, image is corrupted.")
    exit(1)

nx_len = int(x_len / 2)

binary_string = ""
x_len = x_len - 1

for i in range(0, y_len):
    for j in range(0, nx_len):

        if image_matrix[j, i] != image_matrix[x_len - j, i]:
            binary_string += str(image_matrix[x_len - j, i][2] - image_matrix[j, i][2])

decimal_representation = int(binary_string, 2)
hexadecimal_string = hex(decimal_representation)

os.system("echo \"%s\" | xxd -r -ps > flag_decoded.txt" % hexadecimal_string)
image.close()
