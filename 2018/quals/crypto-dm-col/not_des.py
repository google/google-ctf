#!/usr/bin/env python3
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import functools
import struct

KEY_SIZE = 8
BLOCK_SIZE = 8

# yapf: disable
# Note the 1-based indexing in all the following tables.
IP = [
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17,  9 ,1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7,
]

IP_INV = [
  40,  8, 48, 16, 56, 24, 64, 32,
  39,  7, 47, 15, 55, 23, 63, 31,
  38,  6, 46, 14, 54, 22, 62, 30,
  37,  5, 45, 13, 53, 21, 61, 29,
  36,  4, 44, 12, 52, 20, 60, 28,
  35,  3, 43, 11, 51, 19, 59, 27,
  34,  2, 42, 10, 50, 18, 58, 26,
  33,  1, 41,  9, 49, 17, 57,25,
]

E = [
  32,  1,  2,  3,  4,  5,
   4,  5,  6,  7,  8,  9,
   8,  9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32,  1,
]

PC1_C = [
  57, 49, 41, 33, 25, 17,  9,
   1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27,
  19, 11,  3, 60, 52, 44, 36,
]

PC1_D = [
  63, 55, 47, 39, 31, 23, 15,
   7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29,
  21, 13,  5, 28, 20, 12,  4,
]

PC2 = [
  14, 17, 11, 24,  1, 5,
   3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26, 8,
  16,  7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55,
  30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53,
  46, 42, 50, 36, 29, 32,
]

KS_SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

P = [
  16,  7, 20, 21,
  29, 12, 28, 17,
   1, 15, 23, 26,
   5, 18, 31, 10,
   2,  8, 24, 14,
  32, 27,  3,  9,
  19, 13, 30,  6,
  22, 11,  4, 25,
]

S1 = [
  [14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9, 0,  7],
  [ 0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5, 3,  8],
  [ 4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10, 5,  0],
  [15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0, 6, 13],
]

S2 = [
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
  [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
  [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
  [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
]

S3 = [
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
  [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
  [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
  [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
]

S4 = [
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
  [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
  [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
  [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
]

S5 = [
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
  [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
  [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
  [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
]

S6 = [
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
  [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
  [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
  [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
]

S7 = [
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
  [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
  [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
  [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
]

S8 = [
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
  [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
  [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
  [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]

# yapf: enable

SBOXES = [S6, S4, S1, S5, S3, S2, S8, S7]


def Xor(b1, b2):
  """Xors two bit vectors together."""
  return [x ^ y for x, y in zip(b1, b2)]


def Concat(*vectors):
  """Concats vectors."""
  return functools.reduce(lambda x, y: x + y, vectors, [])


def Str2Bits(s):
  """Converts a string to a vector of bits."""
  assert (isinstance(s, bytes))

  def Char2Bits(num):
    bits = bin(num)[2:]
    bits = '0' * (8 - len(bits)) + bits
    return [int(b) for b in bits]

  return Concat(* [Char2Bits(c) for c in s])


def Bits2Str(v):
  """Converts a vector of bits to a string."""

  def Bits2Char(byte):
    return struct.pack('>B', int(''.join([str(b) for b in byte]), 2))

  return b''.join([Bits2Char(v[8 * i:8 * i + 8]) for i in range(len(v) // 8)])


def Expand(v):
  """Expands 32bits into 48 bits."""
  assert (len(v) == 32)
  return [v[E[i] - 1] for i in range(48)]


def LeftShift(v, t=1):
  """Left shitfs (rotates) a vector of bits t times."""
  return v[t:] + v[:t]


def KeyScheduler(key):
  """Yields round keys."""
  assert (len(key) == 64)
  # Only 56 bits are used. A bit in each byte is reserved for pairity checks.
  C = [key[PC1_C[i] - 1] for i in range(28)]
  D = [key[PC1_D[i] - 1] for i in range(28)]

  for ri in range(16):
    C = LeftShift(C, KS_SHIFTS[ri])
    D = LeftShift(D, KS_SHIFTS[ri])

    CD = Concat(C, D)
    ki = [CD[PC2[i] - 1] for i in range(48)]
    yield ki


def CipherFunction(key, inp):
  """Single confusion-diffusion step."""
  assert (len(key) == 48)
  assert (len(inp) == 32)

  # Confusion step.
  res = Xor(Expand(inp), key)
  sbox_out = []
  for si in range(48 // 6):
    sbox_inp = res[6 * si:6 * si + 6]
    sbox = SBOXES[si]
    row = (int(sbox_inp[0]) << 1) + int(sbox_inp[-1])
    col = int(''.join([str(b) for b in sbox_inp[1:5]]), 2)

    bits = bin(sbox[row][col])[2:]
    bits = '0' * (4 - len(bits)) + bits
    sbox_out += [int(b) for b in bits]

  # Diffusion step.
  res = sbox_out
  res = [res[P[i] - 1] for i in range(32)]
  return res


def DESEncrypt(plaintext, key):
  if isinstance(key, bytes):
    key = Str2Bits(key)
    assert (len(key) == 64)
  if isinstance(plaintext, bytes):
    plaintext = Str2Bits(plaintext)

  # Initial permutation.
  plaintext = [plaintext[IP[i] - 1] for i in range(64)]
  L, R = plaintext[:32], plaintext[32:]

  # Feistel network.
  for ki in KeyScheduler(key):
    L, R = R, Xor(L, CipherFunction(ki, R))

  # Final permutation.
  ciphertext = Concat(R, L)
  ciphertext = [ciphertext[IP_INV[i] - 1] for i in range(64)]

  return Bits2Str(ciphertext)


def DESDecrypt(ciphertext, key):
  if isinstance(key, bytes):
    key = Str2Bits(key)
    assert (len(key) == 64)
  if isinstance(ciphertext, bytes):
    ciphertext = Str2Bits(ciphertext)

  # Initial permutation.
  ciphertext = [ciphertext[IP[i] - 1] for i in range(64)]
  L, R = ciphertext[:32], ciphertext[32:]

  # Feistel network.
  for ki in reversed(list(KeyScheduler(key))):
    L, R = R, Xor(L, CipherFunction(ki, R))

  # Final permutation.
  plaintext = Concat(R, L)
  plaintext = [plaintext[IP_INV[i] - 1] for i in range(64)]

  return Bits2Str(plaintext)
