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
# NOTE: You need to comment out crc checking & encryption bit checking in the
# zipfile module (just copy it to te directory with solver.py and patch it
# locally).
import zipfile
import hashlib
from z3 import *
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

def split_bits(byte, sz=8):
  return [
    (byte >> i) & 1 for i in xrange(sz)
  ]

def rsplit_bits(byte, sz=8):
  return [
    (byte >> i) & 1 for i in xrange(sz - 1, -1, -1)
  ]


def known_keystream(data, known):
  ks = []
  for offset, known_data in known:
    known_data = bytearray(known_data)
    if offset is None:
      continue # TODO(gynvael): Add support

    if offset < 0:
      offset += len(data)

    for i, (act_byte, known_byte) in enumerate(zip(
        data[offset:offset + len(known_data)], known_data)):
      ks.append((offset + i, split_bits(act_byte ^ known_byte)))

  return ks

def general_lsfr_iterate(poly, r):
  new_bit = BitVecVal(1, 1)
  for i in xrange(POLY_SZ):
    new_bit = new_bit ^ (Extract(i, i, poly) & Extract(i, i, r))

  new_r = Concat(Extract(POLY_SZ - 2, 0, r), new_bit)
  gen_bit = Extract(POLY_SZ - 1, POLY_SZ - 1, r)

  return (new_r, gen_bit)


def solve(key_iv, cipher_iv, data, enc_hash, known):
  org_key_iv = key_iv
  org_cipher_iv = cipher_iv

  ks = known_keystream(data, known)
  end_offset = max(k[0] for k in ks) + 1
  print "Number of known bytes:", len(ks)
  print "Number of usable bytes:", (len(ks) - POLY_SZ)
  print "End state offset:", end_offset

  poly = []
  for i in xrange(8):
    poly.append(BitVec("poly_%i" % i, POLY_SZ))

  r = []
  cipher_iv = BitStream(org_cipher_iv)
  for i in xrange(8):
    r.append(BitVecVal(cipher_iv.get_bits(POLY_SZ), POLY_SZ))

  print "Adding states..."
  sys.stdout.flush()

  state = []
  for j in xrange(end_offset):
    if j % 65 == 0:
      sys.stdout.write("--> %i / %i\r" % (j, end_offset))
      sys.stdout.flush()
    s = []
    for i in xrange(8):
      new_r, gen_bit = general_lsfr_iterate(poly[i], r[i])
      r[i] = new_r
      s.append(gen_bit)
    state.append(s)

  print "Done!                             "

  print "Solving..."
  sys.stdout.flush()

  s = Solver()
  for offset, bits in ks:
    for i in xrange(8):
      s.add(state[offset][i] == bits[i])

  res = s.check()

  key_iv = BitStream(org_key_iv)
  key_xor = BitVecVal(key_iv.get_bits(POLY_SZ * 8), POLY_SZ * 8)

  while res.r == 1:
    m = s.model()

    key_bv = poly[0]
    for i in xrange(1, 8):
      key_bv = Concat(poly[i], key_bv)

    key = m.eval(key_bv ^ key_xor).as_long()
    key = hex(key)[2:-1].decode('hex')[::-1]

    print "Key:", `key`, len(key)

    if len(key) == POLY_SZ:
      # Try it.
      d = LFSRCipher(key, POLY_SZ, org_key_iv, org_cipher_iv)
      dec = d.crypt(data)
      dec_hash = d.crypt(enc_hash)
      act_hash = hashlib.sha256(dec).digest()
      print "hash match:", act_hash == dec_hash
      if act_hash == dec_hash:
        with open("dump_%s.png" % key.encode("hex"), "wb") as f:
          f.write(dec)

    s.add(key_bv != m.eval(key_bv).as_long())

    res = s.check()
  print res

  return key

# Fun fact: this requires a hacked zipfile module which ignores the
# 'encrypted' flag and crc32 errors.
z = zipfile.ZipFile("../attachments/flag.zip")
data = z.read("flag.png")

key_iv = data[:POLY_SZ]
cipher_iv = data[POLY_SZ:POLY_SZ*2]
enc = bytearray(data[POLY_SZ*2:-32])
enc_hash = data[-32:]

known = [
  (0, "89504E470D0A1A0A".decode('hex')),  # PNG magic
  (8, "0000000D".decode('hex')),  # IHDR length
  (0x0c, "IHDR"),  # IHDR
  (0x10, "\0\0"),  # Width, last two bytes 0 (BE)
  (0x10 + 4, "\0\0"),  # Height, last two bytes 0 (BE)
  (0x18, "\x08"),  # Bit depth (1, 2, 4, 8 or 16)
  (0x19, "\2"),  # Color type, probably 2 (possible values: 0, 2, 3, 4, 6)
  (0x1A, "\0"),  # Compression method.
  (0x1B, "\0"),  # Filter method.
  (0x1C, "\0"),  # Interlace method, must be 0 or 1, assuming 0
  (0x1D + 4, "\0\0\0\1"),  # Length of IDAT will be \0\0 or \0\1
  (0x1D + 8, "sRGB\0\xae\xce\x1c\xe9\0\0"),  # IDAT will have to be there. Probably.
  #(-12, "0000000049454E44AE426082".decode('hex')),  # full IEND header
]

key = solve(key_iv, cipher_iv, enc, enc_hash, known)
#print "Key:", `key`




