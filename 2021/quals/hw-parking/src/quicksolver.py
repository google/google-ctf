# Copyright 2021 Google LLC
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

CONST_A = 0
for i in range(100):
    CONST_A |= 0xdeadc0de << (32 * i)
CONST_B = 0
for i in range(100):
    CONST_B |= 0x13371337 << (32 * i)
FLAG_CONST = int(open("/tmp/fc").read())
BITS = 8*8
MASK = (2**BITS)-1
if 0:
    for flag in range(1<<BITS):
        x = (flag ^ CONST_A) & MASK
        x = (x * 3) & MASK
        x = (x ^ (x>>1)) & MASK
        x = ((x>>1) | (x<<(BITS-1))) & MASK
        x = (x + CONST_B) & MASK
        x = (x ^ FLAG_CONST) & MASK
        if x == 0:
            print("bruted flag:", flag)

x = 0
# x = (x ^ FLAG_CONST) & MASK
x ^= FLAG_CONST
x &= MASK
# x  = (x + CONST_B) & MASK
x -= CONST_B & MASK
x += 2**BITS
x &= MASK
# x = ((x>>1) | (x<<(BITS-1))) & MASK
x = ((x<<1) | (x>>(BITS-1))) & MASK

# x = (x ^ (x>>1)) & MASK
# https://marc-b-reynolds.github.io/math/2017/10/13/IntegerBijections.html
# This is grey code, inverse is this loop:
i = 1
while i < 2**BITS:
    x = (x ^ (x>>i)) & MASK
    i *= 2

# x = (x * 3) & MASK
x = (x * pow(3, -1, 2**BITS)) & MASK
# x = (x ^ CONST_A) & MASK
x ^= CONST_A
x &= MASK




print(bytes.fromhex(hex(x)[2:])[::-1])

