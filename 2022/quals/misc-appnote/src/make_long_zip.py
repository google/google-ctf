# Copyright 2022 Google LLC
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

from struct import pack, unpack
import string
import zlib

def make_lfh(data, name, contents):
  crc = zlib.crc32(contents)
  sz = len(contents)
  data.extend(
      pack("<IHHHHHIIIHH", 0x04034b50, 0, 0, 0, 0, 0, crc, sz, sz, len(name), 0)
  )
  data.extend(name)
  data.extend(contents)

def make_cdfh(data, name, contents, off):
  crc = zlib.crc32(contents)
  sz = len(contents)
  data.extend(
      pack("<IHHHHHHIIIHHHHHII", 0x02014b50, 0, 0, 0, 0, 0, 0, crc, sz, sz, len(name),
           0, 0, 0, 0, 0, off)
  )
  data.extend(name)

def make_eocd(data, cdoff, cdsz, commentlen, nfiles):
  data.extend(
      pack("<IHHHHIIH", 0x06054b50, 0, 0, nfiles, nfiles, cdsz, cdoff, commentlen)
  )

def make_file(data, fname, contents):
  off = len(data)
  make_lfh(data, fname, contents)
  off_cd = len(data)
  make_cdfh(data, fname, contents, off)
  return off_cd, len(data) - off_cd

"""
data = bytearray()

off = len(data)
make_lfh(data, b"lol", b"xd")
off_cd = len(data)
make_cdfh(data, b"lol", b"xd", off)
off_cd_end = len(data)

make_eocd(data, off_cd, off_cd_end-off_cd, 22)
off2 = len(data)
make_eocd(data, off_cd, off2-off_cd, 0)

print(data)

open("dump.zip", "wb").write(data)
"""


FLAG = "CTF{Pos7m0dern_z1p_4rt_an4ly5is}"
ALPHABET = string.ascii_letters + string.digits + "{}_"

data = bytearray()

off_hello_cd, hello_cd_sz = make_file(
    data, b"hello.txt", b"There's more to it than meets the eye...\n")
off_hello_cd2, hello_cd_sz2 = make_file(
    data, b"hi.txt", b"Find a needle in the haystack...\n")

good = []
for char_ind in range(len(FLAG)):
  for alph in ALPHABET:
    off, sz = make_file(data, b"flag%02d" % char_ind, bytes([ord(alph)]))
    if FLAG[char_ind] == alph:
      good.append((off, sz))

make_eocd(data, off_hello_cd2, len(data) - off_hello_cd2, 22*(len(FLAG)+1), 1)

for i in range(len(FLAG)):
  off, sz = good[i]
  make_eocd(data, off, len(data) - off, 22*(len(FLAG) - i), 1)

make_eocd(data, off_hello_cd, len(data) - off_hello_cd, 0, 1)

open("dump.zip", "wb").write(data)
