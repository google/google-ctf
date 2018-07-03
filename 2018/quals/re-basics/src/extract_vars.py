#!/usr/bin/python
# Copyright 2018 Google LLC
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
#
#
# A small tool to dump in-memory BASIC variables from a VICE image. It's kind
# of a hack, but works well enough for debugging.

import sys
from struct import pack, unpack

def rb(v):
  return unpack("<B", str(v[0]))[0]

def rw(v):
  return unpack("<H", str(v[:2]))[0]

def rwBE(v):
  return unpack(">H", str(v[:2]))[0]

def rd(v):
  return unpack("<I", str(v[:4]))[0]

def rdBE(v):
  return unpack(">I", str(v[:4]))[0]

def rq(v):
  return unpack("<Q", str(v[:8]))[0]

def getname(d, off):

  if d[off] == 0:
    return ""


  v1 = d[off]
  vch = v1 & 0x7f

  o = chr(vch)

  v2 = d[off+1]
  vch = v2 & 0x7f

  if vch != 0:
    o += chr(vch)

  if (v2 & 0x80) and not (v1 & 0x80):
    o += "$"

  if (v1 & 0x80) and (v2 & 0x80):
    o += "%"

  return o


OFFSET = 0x99

if len(sys.argv) != 2:
  sys.exit("usage: extract_vars.py <file.vsf>")

d = bytearray(open(sys.argv[1], "rb").read())[OFFSET:]

VARS = rw(d[0x2d:0x2d+2])
print "vars at 0x%x" % VARS

def fbin(m):
  o = ""
  for i in range(30, -1, -1):
    o += "01"[(m >> i) & 1]

  return o

i = VARS
while True:
  print "%.4x:" % i,
  s = getname(d, i)
  i += 2

  if not s:
    break

  t = "FLOAT"
  if s.endswith('$'):
    t = "STRING"
  elif s.endswith('%'):
    t = "INT"

  print "%7s %-10s" % (t, s),

  if t == "FLOAT":
    exp = d[i] - 128
    i += 1
    ms = rdBE(d[i:i+4])
    i += 4

    s = (ms >> 31) & 1
    m = ms & 0x7fffffff

    fb = fbin(m)
    print "+-"[s], "0.1%s" % fb, "* 2 ** %i  ~ " % (exp),

    v = "%.8x" % (int(fb, 2) << 1)
    st = '0x1.%sp%i' % (v, exp - 1)
    f = float.fromhex(st)
    print "%.15f" % f
  elif t == "STRING":
    l = d[i]
    i += 1
    ptr = rw(d[i:i+2])
    i += 2

    xxx = rw(d[i:i+2])
    i += 2  # Skip whatever.

    s = str(d[ptr:ptr+l])

    print "%i @ %.4x (%.4x): %s" % (l, ptr, xxx, s)

  elif t == "INT":
    v = rwBE(d[i:i+2])
    i += 2

    i += 3
    print "%i (%.4x)" % (v, v)


  else:
    sys.exit(t)






