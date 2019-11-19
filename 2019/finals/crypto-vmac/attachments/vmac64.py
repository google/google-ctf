# Copyright 2019 Google LLC
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

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import struct

# Reference: draft-krovetz-vmac-01.txt
# This only implements VMAC with AES as cipher and 64 bit tags.

BLOCKSIZE = 16  # block size of AES in bytes
L1KEYSIZE = 128  # size of the L1 key in bytes

MASK_POLY = 0x1FFFFFFF1FFFFFFF1FFFFFFF1FFFFFFF
P127 = 2 ** 127 - 1
P64  = 2 ** 64 - 257
PP = 2 ** 64 - 2 ** 32

def nh(k, m):
  mask64 = 0xffffffffffffffff
  res = 0
  for i in range(0, len(m), 2):
    res += ((m[i] + k[i]) & mask64) * ((m[i+1] + k[i+1]) & mask64)
  return res % 2**126

class Vmac64:
  def __init__(self, key: bytes):
    self.cipher = self.create_cipher(key)
    self.l1_keys = self.kdf_int(128, 0, L1KEYSIZE // 8)
    self.l2_keys = self.kdf_int(192, 0, 2)
    idx = 1
    while True:
      k0, k1 = self.kdf_int(224, 2 * (idx - 1), 2 * idx)
      if (k0 < P64) and (k1 < P64):
        self.l3_keys = k0, k1
        break
      idx += 1

  def create_cipher(self, key):
    if isinstance(key, bytearray):
      key = bytes(key)
    assert isinstance(key, bytes) and len(key) in (16, 24, 32)
    return Cipher(algorithms.AES(key), modes.ECB(), default_backend())

  def encrypt_block(self, ba) -> bytes:
    encryptor = self.cipher.encryptor()
    assert len(ba) == 16
    if isinstance(ba, bytearray):
      ba = bytes(ba)
    return encryptor.update(ba) + encryptor.finalize()

  def kdf(self, index: int, size: int) -> bytes:
    if size % BLOCKSIZE > 0:
      return self.kdf(index, size + (-size % BLOCKSIZE))[:size]
    res = bytearray(size)
    for i in range(size // BLOCKSIZE):
      inp = bytes([index] + [0] * 14  + [i])
      res[BLOCKSIZE * i : BLOCKSIZE * (i+1)] = self.encrypt_block(inp)
    return bytes(res)

  def kdf_int(self, index: int, start: int, stop: int):
    ba = self.kdf(index, 8 * stop)
    return struct.unpack('>%dQ' % (stop - start), ba[8 * start: 8 * stop])

  def pdf(self, nonce: bytes) -> bytes:
    index = nonce[-1] % 2
    block = bytearray(BLOCKSIZE - len(nonce)) + nonce
    block[-1] -= index
    enc = self.encrypt_block(bytes(block))
    return enc[8 * index : 8 * (index + 1)]

  def l1_hash(self, m: bytes):
    k = self.l1_keys
    blocks = (len(m) + L1KEYSIZE - 1) // L1KEYSIZE
    fullblocks = len(m) // L1KEYSIZE
    y = [None] * blocks
    cnt = L1KEYSIZE // 8
    fmt = '<%dQ' % cnt
    for i in range(fullblocks):
      pos = i * L1KEYSIZE
      hstr = struct.unpack_from(fmt, m, pos)
      y[i] = nh(k, hstr)
    if blocks > fullblocks:
      pos = fullblocks * L1KEYSIZE
      ba = m[pos : pos + L1KEYSIZE]
      ba += bytes(-len(ba) % 16)
      cnt = len(ba) // 8
      hstr = struct.unpack('<%dQ' % cnt, ba)
      y[fullblocks] = nh(k, hstr)
    return y

  def l2_hash(self, m: bytes, bitlength: int) -> int:
    t0, t1 = self.l2_keys
    k = ((t0 & MASK_POLY) << 64) | (t1 & MASK_POLY)
    if len(m) == 0:
      y = k
    else:
      y = 1
      for v in m:
        y = (y * k + v) % P127
    return (y + ((bitlength % (L1KEYSIZE * 8)) << 64)) % P127

  def l3_hash(self, m: int) -> int:
    k0, k1 = self.l3_keys
    m0, m1 = divmod(m, PP)
    return ((k0 + m0) * (k1 + m1)) % P64

  def vhash(self, m: bytes) -> int:
    t1 = self.l1_hash(m)
    t2 = self.l2_hash(t1, 8 * len(m))
    return self.l3_hash(t2)

  def mac(self, m: bytes, nonce: bytes):
    if len(nonce) > 16:
      raise ValueError("Nonce too long")
    elif len(nonce) == 16 and nonce[0] >= 128:
      raise ValueError("Nonce must be smaller than 128-bits")
    v = self.vhash(m)
    m = struct.unpack('>Q', self.pdf(nonce))[0]
    tag = (m + v) % 2 ** 64
    return struct.pack('>Q', tag)

  def tag(self, m: bytes, nonce: bytes) -> str:
    return self.mac(m, nonce)
