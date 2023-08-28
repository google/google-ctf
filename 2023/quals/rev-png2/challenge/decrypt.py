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
import sys
import struct
import zlib


data = open(sys.argv[1], "rb").read()
assert data[:8] == b"\x89PNG\r\n\x1a\n"

data = data[8:]
def get_chunk():
  global data
  length, data = struct.unpack(">I", data[:4])[0], data[4:]
  type, data = data[:4], data[4:]
  chunk, data = data[:length], data[length:]
  _, data = data[:4], data[4:]
  return type, chunk

type, chunk = get_chunk()
assert type == b"IHDR"
w, h = struct.unpack(">II", chunk[:8])
assert w == h
sz = w

type, chunk = get_chunk()
assert type == b"IDAT"

chunk = zlib.decompress(chunk)
assert len(chunk) == 3*sz*sz+sz

# Unfilter.

def apply(filt, cur, left, top, topleft, left2, left3):
  if filt == 0:
    return cur
  elif filt == 1:
    return (cur + left) % 256
  elif filt == 2:
    return (cur + top) % 256
  else:
    if filt == 0xe0:
      return (cur ^ left) % 256
    elif filt == 0xe1:
      return (cur ^ top) % 256
    elif filt == 0xe2:
      return (cur ^ top ^ left ^ topleft) % 256
    elif filt == 0xe3:
      return (cur + left2) % 256
    elif filt == 0xe4:
      return (cur + left3) % 256
    elif filt == 0xe5:
      return (cur ^ left2) % 256
    elif filt == 0xe6:
      return (cur ^ left3) % 256
    elif filt == 0xe7:
      return (cur ^ left ^ left2 ^ left3) % 256
    else:
      return 0

unfiltered = []
k = 0
prev_row = [(0,0,0)] * sz
for i in range(sz):
  filt = chunk[k]
  k += 1
  for j in range(sz):
    tu = []
    for w in range(3):
      cur = chunk[k]
      top = prev_row[j][w]
      left = 0
      topleft = 0
      left2 = 0
      left3 = 0
      if j != 0:
        left = unfiltered[-1][w]
        topleft = prev_row[j-1][w]
        if j > 1:
          left2 = unfiltered[-2][w]
        if j > 2:
          left3 = unfiltered[-3][w]
      tu.append(apply(filt, cur, left, top, topleft, left2, left3))
      k += 1
    unfiltered.append(tuple(tu))
  prev_row = unfiltered[-sz:]

# Reorder.

def d2xy(n, d):
    t = d
    x = y = 0
    s = 1
    while s < n:
      rx = 1 & (t//2)
      ry = 1 & (t ^ rx)
      x, y = rot(s, x, y, rx, ry)
      x += s * rx
      y += s * ry
      t //= 4
      s *= 2
    return x, y

def rot(n, x, y, rx, ry):
  if (ry == 0):
    if (rx == 1):
            x = n-1 - x;
            y = n-1 - y;

    t  = x;
    x = y;
    y = t;
  return x, y

pixels = [0] * (sz*sz)
for i in range(sz*sz):
  x, y = d2xy(sz, i)
  pixels[y * sz + x] = unfiltered[i]

im = Image.new("RGB", (sz, sz))
im.putdata(pixels)
im.save(sys.argv[2])
