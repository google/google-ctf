# Copyright 2024 Google LLC
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

#!/usr/bin/python3

square = [
    0,0,0,0,
    0,1,1,0,
    0,1,1,0,
    0,0,0,0,
]

square = [square]*4

line = [
    [
        1,1,1,1,
        0,0,0,0,
        0,0,0,0,
        0,0,0,0,
    ],
    [
        0,1,0,0,
        0,1,0,0,
        0,1,0,0,
        0,1,0,0,
    ],
]
line.append(line[0])
line.append(line[1])

tri = [
    [
        0,0,0,0,
        1,1,1,0,
        0,1,0,0,
        0,0,0,0,
    ],
    [
        0,1,0,0,
        1,1,0,0,
        0,1,0,0,
        0,0,0,0,
    ],
    [
        0,1,0,0,
        1,1,1,0,
        0,0,0,0,
        0,0,0,0,
    ],
    [
        0,1,0,0,
        0,1,1,0,
        0,1,0,0,
        0,0,0,0,
    ],
]

l = [
    [
        0,0,0,0,
        1,1,1,0,
        0,0,1,0,
        0,0,0,0,
    ],
    [
        0,1,0,0,
        0,1,0,0,
        1,1,0,0,
        0,0,0,0,
    ],
    [
        1,0,0,0,
        1,1,1,0,
        0,0,0,0,
        0,0,0,0,
    ],
    [
        0,1,1,0,
        0,1,0,0,
        0,1,0,0,
        0,0,0,0,
    ],
]

thing = [
    [
        0,0,1,0,
        0,1,1,0,
        0,1,0,0,
        0,0,0,0,
    ],
    [
        0,0,0,0,
        1,1,0,0,
        0,1,1,0,
        0,0,0,0,
    ],
    [
        0,1,0,0,
        1,1,0,0,
        1,0,0,0,
        0,0,0,0,
    ],
    [
        1,1,0,0,
        0,1,1,0,
        0,0,0,0,
        0,0,0,0,
    ],
]



pieces = [square, l, tri, thing, line]

b = ""
for piece in pieces:
    for rot in piece:
        p1 = rot[:8]
        b1 = 0
        for p in p1:
            b1 <<= 1
            if p != 0:
                b1 |= 1
        p2 = rot[8:]
        b2 = 0
        for p in p2:
            b2 <<= 1
            if p != 0:
                b2 |= 1
        b += chr(b1) + chr(b2)

print("\npieces:")
print("".join(["\\x%02x" % ord(c) for c in b]))
print(len(b))


banner = """
.......XXXXXX.......
.....XX......XX.....
....X..........X....
....X..........X....
...X............X...
...XX..........XX...
..XXXXXXX..XXXXXXX..
..X.XXXXXXXXXXXX.X..
..X.XX.XXXXXXXXX.X..
..X.XXXXX..XXXXX.X..
...X.XXX....XXX.X...
....X....XX....X....
.....X...XX...X.....
.....X........X.....
.....X..X..X..X.....
......XXXXXXXX......
....................
X.X..X...X.X.X.XX.X.
X.X.X.X.X..X.X.X..XX
XXX.XXX.X..XX..XX.XX
X.X.X.X.X..X.X.X..XX
X.X.X.X..X.X.X.XX.X.
""".strip().split("\n")


b = ""
byte = 0
bit = 0
for line in banner[::-1]:
    for c in line:
        byte <<= 1
        if c == "X":
            byte |= 1
        bit += 1
        if bit == 8:
            b += chr(byte)
            byte = 0
            bit = 0
assert(bit == 0)
print("\nbanner:")
print("".join(["\\x%02x" % ord(c) for c in b]))
