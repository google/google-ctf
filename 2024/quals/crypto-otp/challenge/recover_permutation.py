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
import glob
from PIL import Image


imgs = []
for g in sorted(glob.glob(sys.argv[1] + "/*")):
  img = Image.open(g).convert("RGBA")
  imgs.append(list(img.getdata()))
  sz = img.size

pixels = []
for i in range(sz[0]):
  for j in range(sz[1]):
    px = [img[i*sz[0]+j] for img in imgs]
    pixels.append(tuple(px))

imgs = []
for g in sorted(glob.glob(sys.argv[2] + "/*.png")):
  img = Image.open(g).convert("RGBA")
  imgs.append(list(img.getdata()))
  sz = img.size

pixels2 = []
for i in range(sz[0]):
  for j in range(sz[1]):
    px = [img[i*sz[0]+j] for img in imgs]
    pixels2.append(tuple(px))


px2idx = {}
for i, px in enumerate(pixels):
  px2idx[px] = i

perm = [-1] * sz[0] * sz[1]
for i, px in enumerate(pixels2):
  perm[px2idx[px]] = i

open("recovered.key", "w").write(str(perm))
