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

# for non-pypy
import pickle
from PIL import Image

TILESIZE = 12

tiles = """
down branchright - crossoverright and nor xor diaginv diaginh diagoutv
diagouth downright - - - mult1 mult2 multcarryprop 0 1
not input - - - mult3 mult4 multiny multinc add1
multins multinx multinyv multincv - mult5 mult6 multoutright multoutdown add2
diag diagcorner addin addindown - - - - check0 check1
"""
tiledata = {}

colors = {
    (63, 0, 111): 1,  # 0 constraint
    (100, 95, 0): 2,  # 1 constraint
    (0, 100, 7): 3,  # 2 constraint
    (0, 0, 0): 0,  # wall
    (255, 255, 255): 5,  # empty
    (255, 0, 0): 5,  # empty
    (0, 255, 0): 10,  # flag bit
    (0, 0, 255): 5,  # empty
}

im = Image.open('tiles.png')
for r, line in enumerate(tiles.strip().splitlines()):
  for c, tile in enumerate(line.split()):
    ymin = 4
    ymax = ymin + 1
    xmin = 9
    xmax = xmin + 1
    arr = []
    for y in range(r * TILESIZE, (r + 1) * TILESIZE):
      l = []
      for x in range(c * TILESIZE, (c + 1) * TILESIZE):
        l.append(colors[im.getpixel((x, y))])
      arr.append(l)
    tiledata[tile] = arr

with open('tiledata.pickle', 'wb') as f:
  pickle.dump(tiledata, f)
