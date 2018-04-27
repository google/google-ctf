#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys

with open(sys.argv[1]) as f:
    content = f.read()
target = 'Try again!\x00'
width = 128
height = 64
idx = content.index(target) + len(target)
img = [ord(x) for x in content[idx:idx+((width*height)/8)]]

res = ""
for bit_idx in range(height * width):
    img_byte = img[bit_idx / 8]
    pixel = bin(img_byte)[2:].zfill(8)[bit_idx % 8]
    if pixel == "0":
        res += ' '
    else:
        res += '#'
    if bit_idx % width == 0:
        res += '\n'
print res
