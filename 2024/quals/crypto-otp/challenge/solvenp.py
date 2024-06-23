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
import sys
import numpy as np
import ast
import random
import glob
from PIL import Image

imgs = []
names = []
for g in glob.glob(sys.argv[1] + "/*"):
  img = Image.open(g).convert("RGBA")
  names.append(g.split("/")[-1])
  imgs.append(img)
  sz = img.size

out = sys.argv[2]

pixels_lists = []
for num in range(len(imgs)):
  pixels = imgs[num].getdata()
  pixels_lists.append(pixels)
pixels_lists = np.array(pixels_lists)

print(sz)
def score(i, j):
  s = 0
  ij = i * sz[0] + j
  if i > 0 and i < sz[0] - 1 and j > 0 and j < sz[1] - 1:
    this = pixels_lists[:, ij]
    this2 = pixels_lists[:, ij - sz[0]]
    this3 = pixels_lists[:, ij + sz[0]]
    this4 = pixels_lists[:, ij - 1]
    this5 = pixels_lists[:, ij + 1]
    x = (
         (this - this2) ** 2 +
         (this - this3) ** 2 +
         (this - this4) ** 2 +
         (this - this5) ** 2
    )
    s += x.sum()
  else:
    for pixels in pixels_lists:
      this = pixels[ij]
      for ii, jj in [(i-1, j), (i+1, j), (i, j-1), (i, j+1)]:
        if ii < 0 or ii >= sz[0] or jj < 0 or jj >= sz[1]: continue
        close = pixels[ii * sz[0] + jj]
        for x, y in zip(this, close):
          s += (x - y) ** 2
  return s

def scoredelta(i1, j1, i2, j2):
  s = 0
  if (i1 > 0 and i1 < sz[0] - 1 and j1 > 0 and j1 < sz[1] - 1 and
      i2 > 0 and i2 < sz[0] - 1 and j2 > 0 and j2 < sz[1] - 1):
    ij1 = i1 * sz[0] + j1
    ij2 = i2 * sz[0] + j2
    c_minus_d = (pixels_lists[:, ij1] - pixels_lists[:, ij2]) * -2
    idxs = [ij1-1, ij1+1, ij1-sz[0], ij1+sz[0],
            ij2-1, ij2+1, ij2-sz[0], ij2+sz[0]]
    amb = pixels_lists[:, idxs]
    amb = amb[:, :4] - amb[:, 4:]
    amb = amb[:, :2] + amb[:, 2:]
    amb = amb[:, 0] + amb[:, 1]
    x = (c_minus_d * amb)
    return x.sum()

  else:
    #TODO
    return 0


improved_since = 0
improved_since_n = 0
for iteration in range(1, 10 * 1000 * 1000):
  T = 50000 * 0.99**(iteration/10000)
  if 1:
    i1 = random.randint(0, sz[0]-1)
    j1 = random.randint(0, sz[1]-1)
    if 1:
      i2 = random.randint(0, sz[0]-1)
      j2 = random.randint(0, sz[1]-1)
    else:
      i2 = random.randint(max(0, i1 - 10), min(sz[0]-1, i1 + 10))
      j2 = random.randint(max(0, j1 - 10), min(sz[1]-1, j1 + 10))

  ij1 = i1 * sz[0] + j1
  ij2 = i2 * sz[0] + j2

  prevcur = scoredelta(i1, j1, i2, j2)
  if 1:
    swap = False
    prob = 2**(prevcur / T)
    if prevcur >= 0:
      swap = True
    elif random.random() < prob:
      swap = True
      print("Random swap, T =", T, "; prob =", prob, " ; delta =", prevcur)

    if prevcur > 0:
      pixels_lists[:, ij1, :], pixels_lists[:, ij2, :] = pixels_lists[:, ij2, :].copy(), pixels_lists[:, ij1, :].copy()
      improved_since += prevcur
      improved_since_n += 1


  n = 100 * 1000
  if iteration % n == 0:
    print("Save", iteration)
    print("  Improved:", improved_since / n, improved_since_n / n * 100)
    print("T", T)
    improved_since = 0
    improved_since_n = 0
    if 1:
      for name, pixels in zip(names, pixels_lists):
        px = list(tuple(p) for p in pixels)
        img.putdata(px)
        img.save(out + "/" + name)
