# Copyright 2023 Google LLC
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

from struct import pack

f = open("gradebook", "wb")

def st(n, s):
  s = s.encode()
  s += b'\x00' * (n-len(s))
  return s

grades = [
    ("S-202", "BIOLOGY 2", "A+", "LIGGET", 3, "214"),
    ("E-314", "ENGLISH 11B", "D", "TURMAN", 5, "172"),
    ("H-221", "WORLD HISTORY 11B", "C", "DWYER", 2, "108"),
    ("M-106", "TRIG 2", "B", "DICKERSON", 4, "315"),
    ("PE-02", "PHYSICAL EDUCATION", "C", "COMSTOCK", 1, "GYM"),
    ("M-122", "CALCULUS 1", "B", "LOGAN", 6, "240"),
    #("12345678", "1234567890123456789012", "D-", "123412341234", 12, "1234"),
]

HSZ = 96
GSZ = 64

EMPTY = 5

f.write(b"GR\xad\xe5") # Magic
f.write(pack("<I", 2023)) # Year
f.write(st(32, "David L.")) # Name
f.write(st(32, "Lightman")) # Name
f.write(pack("<Q", HSZ+len(grades)*GSZ+GSZ*EMPTY)) # File size
f.write(pack("<Q", HSZ)) # First grade offset
f.write(pack("<Q", HSZ+len(grades)*GSZ)) # Empty space offset

for i, (cl, ct, gr, tea, per, room) in enumerate(grades):
  f.write(st(8, cl))
  f.write(st(22, ct))
  f.write(st(2, gr))
  f.write(st(12, tea))
  f.write(st(4, room))
  f.write(pack("<Q", per))

  off = HSZ+(i+1)*GSZ
  if i == len(grades) - 1:
    off = 0
  f.write(pack("<Q", off))

for i in range(EMPTY):
  f.write(b'\x00' * GSZ)
f.close()
