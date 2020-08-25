# Copyright 2020 Google LLC
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

import random
import string
import struct
import sys

random.seed(1337)

arr = []
for i in range(100):
    val = 0x21 + i
    if val >= 0x80:
        val = 0x41 ^ 196 ^ (i-0x80+0x21)
    s = b'97uS' + bytes([val]) + b'aAA'
    h = 0x12345678 ^ struct.unpack("<I", s[:4])[0] ^ struct.unpack("<I", s[4:])[0]
    arr.append((h, s))

arr.sort()
arr = arr[1:] + [arr[0]]
#arr = [arr[0]] + arr[2:] + [arr[1]]


for h, s in arr:
    sys.stdout.buffer.write(b'1 ' + s + b' 0 ')

sys.stdout.buffer.write(b'2 ')

sys.stdout.buffer.write(b'3 ')
sys.stdout.buffer.write(arr[0][1])
sys.stdout.buffer.write(b' 12:34 ')
sys.stdout.buffer.write(arr[-5][1])

sys.stdout.buffer.write(b' 2 ')

sys.stdout.buffer.write(b'3 ')
sys.stdout.buffer.write(arr[-1][1])
sys.stdout.buffer.write(b' 12:34 ')
sys.stdout.buffer.write(arr[-1][1])

sys.stdout.buffer.write(b' 4 ')
