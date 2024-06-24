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

print(sz)

out = sys.argv[2]

pixels_lists = []
for num in range(len(imgs)):
  pixels = list(imgs[num].getdata())
  pixels_lists.append(pixels)

def score(i, j):
  s = 0
  for pixels in pixels_lists:
    this = pixels[i * sz[0] + j]
    for ii, jj in [(i-1, j), (i+1, j), (i, j-1), (i, j+1)]:
      if ii < 0 or ii >= sz[0] or jj < 0 or jj >= sz[1]: continue
      close = pixels[ii * sz[0] + jj]
      for x, y in zip(this, close):
        s += (x - y) ** 2
  return s

improved_since = 0
for iteration in range(10 * 1000 * 1000):
  i1 = random.randint(0, sz[0]-1)
  j1 = random.randint(0, sz[1]-1)
  if 0:
    i2 = random.randint(0, sz[0]-1)
    j2 = random.randint(0, sz[1]-1)
  else:
    i2 = random.randint(max(0, i1 - 10), min(sz[0]-1, i1 + 10))
    j2 = random.randint(max(0, j1 - 10), min(sz[1]-1, j1 + 10))

  prev = score(i1, j1) + score(i2, j2)
  for pixels in pixels_lists:
    pixels[i1*sz[0]+j1] , pixels[i2*sz[0]+j2] = pixels[i2*sz[0]+j2] , pixels[i1*sz[0]+j1]
  cur = score(i1, j1) + score(i2, j2)
  if cur < prev:
    improved_since += prev - cur
  else:
    for pixels in pixels_lists:
      pixels[i1*sz[0]+j1] , pixels[i2*sz[0]+j2] = pixels[i2*sz[0]+j2] , pixels[i1*sz[0]+j1]


  if iteration % (25 * 100) == 0:
    print("Save", iteration)
    print("  Improved:", improved_since / 25 / 1000)
    improved_since = 0
    for name, pixels in zip(names, pixels_lists):
      img.putdata(pixels)
      img.save(out + "/" + name)
