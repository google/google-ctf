#! /usr/bin/python3
#Copyright 2020 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import struct

class SHA256:

  def __init__(self):
    self.h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c,
        0x1f83d9ab, 0x5be0cd19
    ]

    self.k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]

  def rotate_right(self, v, n):
    w = (v >> n) | (v << (32 - n))
    return w & 0xffffffff

  def compression_step(self, state, k_i, w_i):
    a, b, c, d, e, f, g, h = state
    s1 = self.rotate_right(e, 6) ^ self.rotate_right(e, 11) ^ self.rotate_right(e, 25)
    ch = (e & f) ^ (~e & g)
    tmp1 = (h + s1 + ch + k_i + w_i) & 0xffffffff
    s0 = self.rotate_right(a, 2) ^ self.rotate_right(a, 13) ^ self.rotate_right(a, 22)
    maj = (a & b) ^ (a & c) ^ (b & c)
    tmp2 = (tmp1 + s0 + maj) & 0xffffffff
    tmp3 = (d + tmp1) & 0xffffffff
    return (tmp2, a, b, c, tmp3, e, f, g)

  def compression(self, state, w, round_keys = None):
    if round_keys is None:
      round_keys = self.k
    for i in range(64):
      state = self.compression_step(state, round_keys[i], w[i])
    return state

  def compute_w(self, m):
    w = list(struct.unpack('>16L', m))
    for _ in range(16, 64):
      a, b = w[-15], w[-2]
      s0 = self.rotate_right(a, 7) ^ self.rotate_right(a, 18) ^ (a >> 3)
      s1 = self.rotate_right(b, 17) ^ self.rotate_right(b, 19) ^ (b >> 10)
      s = (w[-16] + w[-7] + s0 + s1) & 0xffffffff
      w.append(s)
    return w

  def padding(self, m):
    lm = len(m)
    lpad = struct.pack('>Q', 8 * lm)
    lenz = -(lm + 9) % 64
    return m + bytes([0x80]) + bytes(lenz) + lpad

  def sha256_raw(self, m, round_keys = None):
    if len(m) % 64 != 0:
      raise ValueError('m must be a multiple of 64 bytes')
    state = self.h
    for i in range(0, len(m), 64):
      block = m[i:i + 64]
      w = self.compute_w(block)
      s = self.compression(state, w, round_keys)
      state = [(x + y) & 0xffffffff for x, y in zip(state, s)]
    return state

  def sha256(self, m, round_keys = None):
    m_padded = self.padding(m)
    state = self.sha256_raw(m_padded, round_keys)
    return struct.pack('>8L', *state)
