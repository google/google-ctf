# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import array
import base64
import gzip
import json
import pickle
import random
import struct
import zlib

TILESIZE = 12
N = 368
MOD = 2**N
MASK = 2**N - 1

"""
logic gates based on: https://kinako-ya.hatenablog.com/entry/2023/09/16/174003

multiplier design:

        |         |
   -----+---------+-----
  |     v         v     |
  |    sin        x     |
  |                     |
<-+-- y             y <-+--
  |                     |
  | add sin + x&y + cin |
  |                     |
<-+-- cout        cin <-+--
  |                     |
  |     x        sout   |
  |     |         |     |
   -----+---------+-----
        v         v

inverted adder design:

        |         |
   -----+---------+-----
  |     v         v     |
  |    ~x        ~y     |
  |                     |
  |   add x + y + cin   |
  |                     |
<-+-- ~cout      ~cin <-+--
  |                     |
  |          s          |
  |          |          |
   ----------+----------
             v
"""

tiles = """
down branchright - crossoverright and nor xor diaginv diaginh diagoutv
diagouth downright - - - mult1 mult2 multcarryprop 0 1
not input - - - mult3 mult4 multiny multinc add1
multins multinx multinyv multincv - mult5 mult6 multoutright multoutdown add2
diag diagcorner addin addindown - - - - check0 check1
"""
tilemap = {}
for i, tile in enumerate(tiles.split()):
  if tile != "-":
    tilemap[tile] = i + 1

with open("tiledata.pickle", "rb") as f:
  tiledata = pickle.load(f)

circuit = {}


# flipx, flipy, rot cw done in that order
def add(r, c, tile, *, flipx=False, flipy=False, rot=0, overwrite=False):
  if (r, c) in circuit and not overwrite:
    raise ValueError(f"collision! {(r,c)} {circuit[(r,c)]} {tile}")
  if tile not in tilemap:
    raise ValueError(f"no tile {tile}")
  circuit[(r, c)] = (tile, flipx, flipy, rot)


def bits2int(x):
  return int("".join(str(i) for i in x), 2)


def int2bits(x):
  l = [int(i) for i in f"{x:b}"]
  return [0] * (N - len(l)) + l


random.seed(31337313373133731337)

flag = "n0w_Imag1ne_iF_th1s_w3r3_A_Mystery_Hunt_PuzZlE"
assert len(flag) * 8 == N
flagbits = []
for i in flag:
  flagbits += [int(x) for x in f"{ord(i):08b}"]

r = 0
c = 0

for i in range(N):
  add(r, i * 2, "input")
r += 1

# xor bits with random and/nors of other bits
for z in range(N):
  for i in range(0, N * 2, 2):
    add(r, i, "down")
    add(r + 1, i, "down")
  x, y = sorted(random.sample(sorted(set(range(N)) - set([z])), 2))
  add(r, x * 2, "branchright", overwrite=True)
  add(r, y * 2, "branchright", flipx=True, overwrite=True)
  if random.random() < 0.5:
    add(r, x * 2 + 1, "and")
    flagbits[z] ^= flagbits[x] & flagbits[y]
  else:
    add(r, x * 2 + 1, "nor")
    flagbits[z] ^= (flagbits[x] | flagbits[y]) ^ 1
  for i in range(x * 2 + 2, y * 2):
    if i % 2 == 0:
      add(r, i, "crossoverright", flipx=True, overwrite=True)
    else:
      add(r, i, "down", rot=1)
  if z * 2 < x * 2 + 1:
    add(r + 1, z * 2, "xor", overwrite=True)
    add(r + 1, x * 2 + 1, "downright", flipx=True)
    for i in range(z * 2 + 1, x * 2 + 1):
      if i % 2 == 0:
        add(r + 1, i, "crossoverright", flipx=True, overwrite=True)
      else:
        add(r + 1, i, "down", rot=1)
  else:
    add(r + 1, z * 2, "xor", flipx=True, overwrite=True)
    add(r + 1, x * 2 + 1, "downright")
    for i in range(x * 2 + 2, z * 2):
      if i % 2 == 0:
        add(r + 1, i, "crossoverright", overwrite=True)
      else:
        add(r + 1, i, "down", rot=3)
  r += 2
print("random xor done")

# multiply/add with constants
mult1 = random.getrandbits(N)
mult1 |= 1  # ensure odd
add1 = random.getrandbits(N)
add2 = random.getrandbits(N)

flagbits = int2bits((bits2int(flagbits) * mult1 + add1 + add2) & MASK)

c -= 1
for i in range(N):
  add(r, c + i * 2, "01"[((add1 >> (N - 1 - i)) & 1) ^ 1])
  add(r, c + i * 2 + 1, "down")
  add(r + 1, c + i * 2, "not")
  add(r + 1, c + i * 2 + 1, "down")
  add(r + 2, c + i * 2, "multins")
  add(r + 2, c + i * 2 + 1, "multinx")
r += 3
for j in range(N):
  for i in range(j, N):
    add(r, c + i * 2 - j, "mult1")
    add(r, c + i * 2 + 1 - j, "mult2")
    add(r + 1, c + i * 2 - j, "mult3")
    add(r + 1, c + i * 2 + 1 - j, "mult4")
    add(r + 2, c + i * 2 - j, "mult5")
    add(r + 2, c + i * 2 + 1 - j, "mult6")
  add(r + 1, c + N * 2 + (j == 0), "01"[(mult1 >> j) & 1], rot=1)
  add(r + 2, c + N * 2 + (j == 0), "01"[(add2 >> j) & 1], rot=1)
  if j == 0:
    add(r + 1, c + N * 2 - j, "multiny")
    add(r + 2, c + N * 2 - j, "multinc")
  else:
    add(r, c + N * 2 - j, "multoutdown")
    add(r + 1, c + N * 2 - j, "multinyv")
    add(r + 2, c + N * 2 - j, "multincv")
    for i in range(3 * (N - j) - 2):
      add(
          r + 3 + i,
          c + N * 2 - j,
          "down" if i % 3 == 0 else "crossoverright",
          flipx=True,
      )
  r += 3
add(r, c + N, "multoutdown")
r += 1
c += N
print("mult const done")

# permute bits
orig = list(range(N))
perm = list(range(N))
random.shuffle(perm)
swaplist = []
swapoffset = 0
while perm != orig:
  swaps = []
  i = 0
  for i in range(swapoffset, N - 1, 2):
    if perm[i] > perm[i + 1]:
      perm[i], perm[i + 1] = perm[i + 1], perm[i]
      flagbits[i], flagbits[i + 1] = flagbits[i + 1], flagbits[i]
      swaps.append(i)
  swapoffset = 1 - swapoffset
  swaplist.append(swaps)

for i in range(N):
  for j in range(i):
    add(r + j, c + i, "down")
  add(r + i, c + i - 1, "diagcorner")
  add(r + i, c + i, "diaginv")
r += 1
c -= 1
for swaps in swaplist:
  i = 0
  while i < N:
    if i in swaps:
      add(r + i, c + i, "diagoutv")
      add(r + i + 1, c + i + 1, "diagouth")
      add(r + i + 1, c + i, "crossoverright", flipx=True)
      add(r + i + 2, c + i - 1, "diagcorner")
      add(r + i + 2, c + i, "diaginv")
      add(r + i + 1, c + i - 2, "diagcorner")
      add(r + i + 1, c + i - 1, "diaginh")
      i += 2
    else:
      add(r + i, c + i, "diag")
      add(r + i, c + i - 1, "diagcorner")
      add(r + i + 1, c + i - 1, "diag")
      add(r + i + 1, c + i - 2, "diagcorner")
      i += 1
  r += 2
  c -= 2
for i in range(N):
  for j in range(N - 1 - i):
    add(r + i + j, c + i - j - 1, "diagcorner")
    add(r + i + j, c + i - j, "diag")
r += N - 1
c -= N - 1
for i in range(N):
  add(r, c + i * 2, "diagoutv")
r += 1
print("permute bits done")

# make last bit 1, so cubing is invertible
if flagbits[-1] == 0:
  for i in range(N - 1):
    add(r, c + i * 2, "down")
    add(r + 1, c + i * 2, "down")
  add(r, c + (N - 1) * 2, "not")
  add(r + 1, c + (N - 1) * 2, "branchright")
  add(r + 1, c + (N - 1) * 2 + 1, "check1", rot=3)
  r += 2
  flagbits[-1] = 1

# split off copy of flagbits for multiplication
for i in range(N):
  for j in range(N):
    add(r + i, c + j * 2, "down")
for i in range(N):
  add(r + i, c + i * 2, "branchright", overwrite=True)
  for j in range(i * 2 + 1, N * 2):
    if j % 2 == 0:
      add(r + i, c + j, "crossoverright", overwrite=True)
    else:
      add(r + i, c + j, "down", rot=3)
  for j in range(N - i):
    add(r + i, c + N * 2 + j, "down", rot=3)
  add(r + i, c + N * 2 + 1 + (N - 1 - i), "downright", flipx=True, rot=3)
  for j in range(N - 1 - i):
    add(r + i + 1 + j, c + N * 2 + 1 + (N - 1 - i), "down")
r += N

for i in range(N):
  for j in range(N * 3 + 3):
    add(r + j, c + N * 2 + 1 + i, "down")
for i in range(N):
  add(
      r + 3 * i + 3,
      c + N * 2 + 1 + i,
      "branchright",
      flipx=True,
      overwrite=True,
  )
  for j in range(i):
    add(
        r + 3 * i + 3,
        c + N * 2 + 1 + j,
        "crossoverright",
        flipx=True,
        overwrite=True,
    )
  for j in range(-2 + (i == 0), 0):
    add(r + 3 * i + 3, c + N * 2 + 1 + j, "down", rot=1)

# multiplication 1
c -= 1
for i in range(N):
  add(r, c + i * 2, "0")
  add(r, c + i * 2 + 1, "down")
  add(r + 1, c + i * 2, "multins")
  add(r + 1, c + i * 2 + 1, "multinx")
r += 2
for j in range(N):
  for i in range(j, N):
    add(r, c + i * 2 - j, "mult1")
    add(r, c + i * 2 + 1 - j, "mult2")
    add(r + 1, c + i * 2 - j, "mult3")
    add(r + 1, c + i * 2 + 1 - j, "mult4")
    add(r + 2, c + i * 2 - j, "mult5")
    add(r + 2, c + i * 2 + 1 - j, "mult6")
  # add(r + 1, c + N * 2 + (j == 0), "01"[(mult1 >> j) & 1], rot=1)
  add(r + 2, c + N * 2 + (j == 0), "0", rot=1)
  if j == 0:
    add(r + 1, c + N * 2 - j, "multiny")
    add(r + 2, c + N * 2 - j, "multinc")
  else:
    add(r, c + N * 2 - j, "multoutdown")
    add(r + 1, c + N * 2 - j, "multinyv")
    add(r + 2, c + N * 2 - j, "multincv")
    for i in range(3 * (N - j) - 2):
      add(
          r + 3 + i,
          c + N * 2 - j,
          "down" if i % 3 == 0 else "crossoverright",
          flipx=True,
      )
  r += 3
add(r, c + N, "multoutdown")
r += 1
c += N

# multiplication 2
for i in range(N):
  for j in range(i):
    add(r + j, c + i, "down")
  if i < N - 1:
    add(r + i, c + i, "downright", flipx=True)
    for j in range(N - 2 - i):
      add(r + i, c + i - 1 - j, "down", rot=1)
    add(r + i, c + i - 1 - (N - 2 - i), "downright", rot=1)
    for j in range(N - 2 - i):
      add(r + i + 1 + j, c + i - 1 - (N - 2 - i), "down")
for i in range(N):
  for j in range(N - 1):
    add(r + j, c + N + 2 + i, "down")
  for j in range(3 * (i + 1)):
    add(r + N - 1 + j, c + N + 2 + i, "down")
  add(r + N - 1 + 3 * (i + 1), c + N + 2 + i, "downright", flipx=True)
  for j in range(-2 + (i == 0), i):
    add(r + N - 1 + 3 * (i + 1), c + N + 2 + j, "down", rot=1)
r += N - 1
c -= N
for i in range(N):
  add(r, c + i * 2, "0")
  add(r, c + i * 2 + 1, "down")
  add(r + 1, c + i * 2, "multins")
  add(r + 1, c + i * 2 + 1, "multinx")
r += 2
for j in range(N):
  for i in range(j, N):
    add(r, c + i * 2 - j, "mult1")
    add(r, c + i * 2 + 1 - j, "mult2")
    add(r + 1, c + i * 2 - j, "mult3")
    add(r + 1, c + i * 2 + 1 - j, "mult4")
    add(r + 2, c + i * 2 - j, "mult5")
    add(r + 2, c + i * 2 + 1 - j, "mult6")
  # add(r + 1, c + N * 2 + (j == 0), "01"[(mult1 >> j) & 1], rot=1)
  add(r + 2, c + N * 2 + (j == 0), "0", rot=1)
  if j == 0:
    add(r + 1, c + N * 2 - j, "multiny")
    add(r + 2, c + N * 2 - j, "multinc")
  else:
    add(r, c + N * 2 - j, "multoutdown")
    add(r + 1, c + N * 2 - j, "multinyv")
    add(r + 2, c + N * 2 - j, "multincv")
    for i in range(3 * (N - j) - 2):
      add(
          r + 3 + i,
          c + N * 2 - j,
          "down" if i % 3 == 0 else "crossoverright",
          flipx=True,
      )
  r += 3
add(r, c + N, "multoutdown")
r += 1
c += N

assert bits2int(flagbits) % 2 == 1
flagbits = int2bits(pow(bits2int(flagbits), 3, MOD))

print("cube done")

# add with constant (to make output factors of bigmult)
for i in range(N):
  for j in range(i):
    add(r + j, c + i, "crossoverright", flipx=True)
  add(r + i, c + i, "addin")
  for j in range(N - i - 1):
    add(r + i + 1 + j, c + i, "addindown")

bigmultp = random.getrandbits(N // 2)
bigmult = bigmultp**2

# adder inputs (+carry in) are inverted
flagbits = (~bits2int(flagbits)) & MASK
total = (bigmultp << (N // 2)) | bigmultp
addbigmult = (total - flagbits) & MASK
addbigmult = (~addbigmult) & MASK

for i in range(N):
  add(r + i, c + N, "01"[(addbigmult >> (N - 1 - i)) & 1], rot=1)
r += N
for i in range(N):
  add(r, c + i, "add1")
  add(r + 1, c + i, "add2")
add(r + 1, c + N, "multinc")
add(r + 1, c + N + 1, "1", rot=1)
r += 2

print("inverted adder done")

# check that halves are identical
for i in range(N // 2 * 3):
  for j in range(N):
    add(r + i, c + j, "down")
for i in range(N // 2):
  add(r + i * 3, c + i, "branchright", overwrite=True)
  for j in range(i + 1, N):
    add(r + i * 3, c + j, "crossoverright", overwrite=True)
  add(r + i * 3 + 1, c + i + N // 2, "branchright", overwrite=True)
  for j in range(i + N // 2 + 1, N):
    add(r + i * 3 + 1, c + j, "crossoverright", overwrite=True)
  add(r + i * 3, c + N, "downright", flipy=True, rot=1)
  add(r + i * 3 + 1, c + N, "xor", flipx=True)
  add(r + i * 3 + 2, c + N, "check0")
r += N // 2 * 3

print("half equality check done")

# multiply halves, check it's bigmult
for i in range(N // 2 + 3):
  for j in range(N // 2):
    add(r + i, c + N // 2 + j, "down")
for i in range(N // 2):
  for j in range(3 * (N // 2 - 1 - i)):
    if j % 3 == 0:
      add(r + N // 2 + 3 + j, c + N // 2 + i, "crossoverright", flipx=True)
    else:
      add(r + N // 2 + 3 + j, c + N // 2 + i, "down")
  add(
      r + N // 2 + 3 + 3 * (N // 2 - 1 - i),
      c + N // 2 + i,
      "downright",
      flipx=True,
  )
  for j in range(-2 + (i == N // 2 - 1), 0):
    add(r + N // 2 + 3 + 3 * (N // 2 - 1 - i), c + N // 2 + j, "down", rot=1)

for i in range(N // 2):
  for j in range(i):
    add(r + j, c + i, "down")
  add(r + i, c + i, "downright", flipx=True)
  for j in range(N // 2 - i):
    add(r + i, c + i - 1 - j, "down", rot=1)
  add(r + i, c + i - 1 - (N // 2 - i), "downright", rot=1)
  for j in range(N // 2 - 1 - i):
    add(r + i + 1 + j, c + i - 1 - (N // 2 - i), "down")
r += N // 2
c -= N // 2 + 2

for i in range(N // 2):
  add(r, c + i * 2, "0")
  add(r, c + i * 2 + 1, "down")
  add(r + 1, c + i * 2, "multins")
  add(r + 1, c + i * 2 + 1, "multinx")
r += 2
for j in range(N // 2):
  add(r + 2, c - j - 1, "multcarryprop")
  for i in range(N // 2):
    add(r, c + i * 2 - j, "mult1")
    add(r, c + i * 2 + 1 - j, "mult2")
    add(r + 1, c + i * 2 - j, "mult3")
    add(r + 1, c + i * 2 + 1 - j, "mult4")
    add(r + 2, c + i * 2 - j, "mult5")
    add(r + 2, c + i * 2 + 1 - j, "mult6")
  add(r + 2, c + N + (j == 0), "0", rot=1)
  if j == 0:
    add(r + 1, c + N - j, "multiny")
    add(r + 2, c + N - j, "multinc")
  else:
    add(r, c + N - j, "multoutdown")
    add(r + 1, c + N - j, "multinyv")
    add(r + 2, c + N - j, "multincv")
    for i in range(3 * (N // 2 - j) - 3):
      add(
          r + 3 + i,
          c + N - j,
          "down" if i % 3 == 0 else "crossoverright",
          flipx=True,
      )
  r += 3
c -= N // 2
for i in range(N // 2 + 1):
  add(r, c + i * 2, "multoutdown")
  add(r + 1, c + i * 2, ["check0", "check1"][(bigmult >> (N - 1 - i)) & 1])
for i in range(N // 2 - 1):
  add(r, c + N + 1 + i, "down")
  add(
      r + 1,
      c + N + 1 + i,
      ["check0", "check1"][(bigmult >> (N - 1 - (i + N // 2 + 1))) & 1],
  )

print("bigmult done: done constructing!")

coords = list(circuit)
rmin = min(i[0] for i in coords)
cmin = min(i[1] for i in coords)
rmax = max(i[0] for i in coords)
height = rmax - rmin + 1
cmax = max(i[1] for i in coords)
width = cmax - cmin + 1

FLIP_X = 1 << 31
FLIP_Y = 1 << 30
FLIP_DIAG = 1 << 29
FLIP_FLAGS = {
    (False, False, 0): 0,
    (True, False, 0): FLIP_X,
    (False, True, 0): FLIP_Y,
    (True, True, 0): FLIP_X | FLIP_Y,
    (False, False, 1): FLIP_X | FLIP_DIAG,
    (True, False, 1): FLIP_X | FLIP_Y | FLIP_DIAG,
    (False, True, 1): FLIP_DIAG,
    (True, True, 1): FLIP_Y | FLIP_DIAG,
    (False, False, 2): FLIP_X | FLIP_Y,
    (True, False, 2): FLIP_Y,
    (False, True, 2): FLIP_X,
    (True, True, 2): 0,
    (False, False, 3): FLIP_Y | FLIP_DIAG,
    (True, False, 3): FLIP_DIAG,
    (False, True, 3): FLIP_X | FLIP_Y | FLIP_DIAG,
    (True, True, 3): FLIP_X | FLIP_DIAG,
}

minimapdata = array.array("I", bytes(4 * height * width))
for (r, c), (tile, flipx, flipy, rot) in circuit.items():
  tid = tilemap[tile] | FLIP_FLAGS[(flipx, flipy, rot)]
  minimapdata[(r - rmin) * width + (c - cmin)] = tid
minimapdata = zlib.compress(minimapdata)
minimapdata = base64.b64encode(minimapdata).decode()
print("done constructing minimap!")
minimap = {
    "compressionlevel": -1,
    "height": height,
    "infinite": False,
    "layers": [{
        "data": minimapdata,
        "encoding": "base64",
        "compression": "zlib",
        "height": height,
        "id": 1,
        "name": "Tile Layer 1",
        "opacity": 1,
        "type": "tilelayer",
        "visible": True,
        "width": width,
        "x": 0,
        "y": 0,
    }],
    "nextlayerid": 2,
    "nextobjectid": 1,
    "orientation": "orthogonal",
    "renderorder": "right-down",
    "tiledversion": "1.8.2",
    "tileheight": 9,
    "tilesets": [{"firstgid": 1, "source": "minimaptiles.json"}],
    "tilewidth": 9,
    "type": "map",
    "version": "1.8",
    "width": width,
}
with open("minimap.json", "w") as f:
  json.dump(minimap, f)
print("wrote minimap")

dataheight = TILESIZE * height
datawidth = TILESIZE * width

data = array.array("B", bytes((dataheight * datawidth) // 2))


def set_tile(r, c, val):
  if not (0 <= r < dataheight and 0 <= c < datawidth):
    return
  idx = r * datawidth + c
  x = data[idx // 2]
  if idx % 2 == 0:
    x = (x & 0xF) | (val << 4)
  else:
    x = (x & 0xF0) | val
  data[idx // 2] = x


def get_tile(r, c):
  if not (0 <= r < dataheight and 0 <= c < datawidth):
    return 0
  idx = r * datawidth + c
  x = data[idx // 2]
  if idx % 2 == 0:
    return x >> 4
  else:
    return x & 0xF


for (r, c), (tile, flipx, flipy, rot) in circuit.items():
  arr = tiledata[tile]
  for r2 in range(TILESIZE):
    for c2 in range(TILESIZE):
      r3 = r2
      c3 = c2
      if flipx:
        c3 = TILESIZE - 1 - c3
      if flipy:
        r3 = TILESIZE - 1 - r3
      match rot:
        case 1:
          r3, c3 = c3, TILESIZE - 1 - r3
        case 2:
          r3, c3 = TILESIZE - 1 - r3, TILESIZE - 1 - c3
        case 3:
          r3, c3 = TILESIZE - 1 - c3, r3
      set_tile(
          (r - rmin) * TILESIZE + r3, (c - cmin) * TILESIZE + c3, arr[r2][c2]
      )

print("done constructing data!")
with gzip.GzipFile("puzzlepuzzle.dat.gz", "wb", mtime=0) as f:
  f.write(struct.pack("<I", datawidth))
  f.write(struct.pack("<I", dataheight))
  f.write(data)
print("wrote data")

# check edges of tiles: there shouldn't be any joined areas or adjacent constraints, except within a macrotile

multtiles = {"mult1", "mult2", "mult3", "mult4", "mult5", "mult6"}
addtiles = {"add1", "add2"}
print("checking edges...")
for (r, c), (tile, _, _, _) in circuit.items():
  if (r + 1, c) in circuit:
    if (tile in multtiles and circuit[(r + 1, c)][0] in multtiles) or (
        tile in addtiles and circuit[(r + 1, c)][0] in addtiles
    ):
      continue
    for i in range(TILESIZE):
      t1 = get_tile(
          (r - rmin) * TILESIZE + (TILESIZE - 1), (c - cmin) * TILESIZE + i
      )
      t2 = get_tile(
          (r - rmin) * TILESIZE + (TILESIZE), (c - cmin) * TILESIZE + i
      )
      if (
          t1 in {1, 2, 3, 4, 15}
          and t2 in {0, 1, 2, 3, 4, 15}
          or t1 in {0, 1, 2, 3, 4, 15}
          and t2 in {1, 2, 3, 4, 15}
      ):
        print(
            "CONFLICT vert (constraint):",
            t1,
            t2,
            (r - rmin, c - cmin),
            i,
            circuit[(r, c)],
            circuit[(r + 1, c)],
        )
      if 5 <= t1 <= 14 and 5 <= t2 <= 14:
        print(
            "CONFLICT vert (area):",
            t1,
            t2,
            (r - rmin, c - cmin),
            i,
            circuit[(r, c)],
            circuit[(r + 1, c)],
        )

  if (r, c + 1) in circuit:
    if (tile in multtiles and circuit[(r, c + 1)][0] in multtiles) or (
        tile in addtiles and circuit[(r, c + 1)][0] in addtiles
    ):
      continue
    for i in range(TILESIZE):
      t1 = get_tile(
          (r - rmin) * TILESIZE + i, (c - cmin) * TILESIZE + (TILESIZE - 1)
      )
      t2 = get_tile(
          (r - rmin) * TILESIZE + i, (c - cmin) * TILESIZE + (TILESIZE)
      )
      if (
          t1 in {1, 2, 3, 4, 15}
          and t2 in {0, 1, 2, 3, 4, 15}
          or t1 in {0, 1, 2, 3, 4, 15}
          and t2 in {1, 2, 3, 4, 15}
      ):
        print(
            "CONFLICT horz (constraint):",
            t1,
            t2,
            (r - rmin, c - cmin),
            i,
            circuit[(r, c)],
            circuit[(r, c + 1)],
        )
      if 5 <= t1 <= 14 and 5 <= t2 <= 14:
        print(
            "CONFLICT horz (area):",
            t1,
            t2,
            (r - rmin, c - cmin),
            i,
            circuit[(r, c)],
            circuit[(r, c + 1)],
        )

print(f"size: {datawidth}x{dataheight}")
filesize = (datawidth * dataheight) // 2 + 8
print(f"{filesize} bytes ({round(filesize/1e9,2)} GB) uncompressed")
print(
    f"script will use ~{round(1.25*filesize/1e9,2)} GB"
)  # 1: puzzle array, 0.25: visited array
