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

import os
import zipfile
import zlib
import hashlib
from struct import pack, unpack
import sys

POLY_SZ = 20


class BitStream:
  def __init__(self, data, sz=None):
    if sz is None:
      sz = len(data) * 8

    self.sz = sz
    self.data = bytearray(data)
    self.idx = 0

  def get_bit(self):
    if self.idx >= self.sz:
      raise Exception('All bits used. Go away.')

    i_byte = self.idx / 8
    i_bit = self.idx % 8

    bit = (self.data[i_byte] >> i_bit) & 1
    self.idx += 1

    return bit

  def get_bits(self, sz):
    v = 0
    for i in xrange(sz):
      v |= self.get_bit() << i

    return v


class LFSR:
  def __init__(self, poly, iv, sz):
    self.sz = sz
    self.poly = poly
    self.r = iv
    self.mask = (1 << sz) - 1

  def get_bit(self):
    bit = (self.r >> (self.sz - 1)) & 1

    new_bit = 1
    masked = self.r & self.poly
    for i in xrange(self.sz):
      new_bit ^= (masked >> i) & 1

    self.r = ((self.r << 1) | new_bit) & self.mask
    return bit


class LFSRCipher:
  def __init__(self, key, poly_sz=8, key_iv=None, cipher_iv=None):
    if len(key) < poly_sz:
      raise Exception('LFSRCipher key length must be at least %i' % poly_sz)
    key = BitStream(key)

    if key_iv is None:
      key_iv = os.urandom(poly_sz)
    self.key_iv = key_iv
    key_iv_stream = BitStream(key_iv)

    if cipher_iv is None:
      cipher_iv = os.urandom(poly_sz)
    self.cipher_iv = cipher_iv
    cipher_iv_stream = BitStream(cipher_iv)

    self.lfsr = []
    for i in xrange(8):
      l = LFSR(key.get_bits(poly_sz) ^ key_iv_stream.get_bits(poly_sz),
               cipher_iv_stream.get_bits(poly_sz), poly_sz)
      self.lfsr.append(l)

  def get_keystream_byte(self):
    b = 0
    for i, l in enumerate(self.lfsr):
      b |= l.get_bit() << i
    return b

  def get_headers(self):
    return self.key_iv + self.cipher_iv

  def crypt(self, s):
    s = bytearray(s)
    for i in xrange(len(s)):
      s[i] ^= self.get_keystream_byte()
    return str(s)


# A super short ZIP implementation.
def SETBIT(n):
  return 1 << n

def db(v):
  return pack("<B", v)

def dw(v):
  return pack("<H", v)

def dd(v):
  return pack("<I", v)


class BetterZipCreator:
  def __init__(self, arcname, key):
    self.key = key
    self.arcname = arcname
    self.files = []

  def add_file(self, fname):
    with open(fname, 'rb') as f:
      data = f.read()
    self.files.append((fname, data))

  def write_lfh(self, arc, f):
    fname, data = f
    crc = zlib.crc32(data) & 0xffffffff

    c = LFSRCipher(self.key, POLY_SZ)
    crypto_headers = c.get_headers()
    encrypted_data = c.crypt(data)

    sha256 = hashlib.sha256(data)
    encrypted_hash = c.crypt(sha256.digest())

    actual_sz = len(crypto_headers) + len(data) + sha256.digest_size

    header_to_write = [
      "PK\3\4",
      dw(90),  # The encryption is so good it's version 9.0 at least!
      dw(SETBIT(0) | SETBIT(15)),  # Super strong encryption enabled!!!
      dw(0),  # No compression.
      dw(0), dw(0),  # Time/date, we don't care.
      dd(crc),
      dd(actual_sz),
      dd(len(data)),
      dw(len(fname)),
      dw(0),  # Extra field length.
      fname
    ]

    arc.write(''.join(header_to_write))
    arc.write(crypto_headers)
    arc.write(encrypted_data)
    arc.write(encrypted_hash)

  def write_cdh(self, arc, f, offset):
    fname, data = f
    crc = zlib.crc32(data) & 0xffffffff

    c = LFSRCipher(self.key, POLY_SZ)
    sha256 = hashlib.sha256(data)
    actual_sz = len(c.get_headers()) + len(data) + sha256.digest_size

    header_to_write = [
      "PK\1\2",
      dw(90),  # The encryption is so good it's version 9.0 at least!
      dw(90),  # The encryption is so good it needs version 9.0 at least!
      dw(SETBIT(0) | SETBIT(15)),  # Super strong encryption enabled!!!
      dw(0),  # No compression.
      dw(0), dw(0),  # Time/date, we don't care.
      dd(crc),
      dd(actual_sz),
      dd(len(data)),
      dw(len(fname)),
      dw(0),  # Extra field length.
      dw(0),  # Comment field length.
      dw(0),  # Disk number start.
      dw(0),  # File attributes.
      dd(0),  # External file attributes.
      dd(offset),
      fname
    ]

    arc.write(''.join(header_to_write))

  def write_eocdh(self, arc, ent_no, cdh_start, cdh_end):
    header_to_write = [
      "PK\5\6",
      dw(0),  # Disk no.
      dw(0),  # Disk with CDH.
      dw(ent_no),
      dw(ent_no),
      dd(cdh_end - cdh_start),
      dd(cdh_start),
      dw(0),  # Comment length.
    ]

    arc.write(''.join(header_to_write))

  def close(self):
    with open(self.arcname, "wb") as arc:
      offsets = []
      crcs = []

      for f in self.files:
        offset = arc.tell()
        offsets.append(offset)

        self.write_lfh(arc, f)

      cdh_start = arc.tell()

      for f, offset in zip(self.files, offsets):
        self.write_cdh(arc, f, offset)

      cdh_end = arc.tell()

      self.write_eocdh(arc, len(self.files), cdh_start, cdh_end)


if len(sys.argv) != 4:
  sys.exit("usage: better_zip.py <arcname.zip> <file> <key_as_hex_string>")

z = BetterZipCreator(sys.argv[1], sys.argv[3].decode('hex'))
z.add_file(sys.argv[2])
z.close()

