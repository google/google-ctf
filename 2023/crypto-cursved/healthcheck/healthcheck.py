#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

from hashlib import sha256
from os import urandom

def bytes_to_hexstr(buf):
  return "".join(["{0:02X}".format(b) for b in buf])
def bytes_to_int(buf):
  return int(bytes_to_hexstr(buf), 16)
def random_int(n):
  return bytes_to_int(urandom(n))
def sha256_as_int(x):
  return int(sha256(x).hexdigest(), 16)
def check_type(x, types):
  if len(x) != len(types):
    return False
  for a,b in zip(x, types):
    if not isinstance(a, b):
      return False
  return True

class Curve:
  def __init__(self, p, D, n):
    self.p = p
    self.D = D
    self.n = n
  def __repr__(self):
    return f"Curve(0x{self.p:X}, 0x{self.D:X})"
  def __eq__(self, other):
    return self.p == other.p and self.D == other.D
  def __matmul__(self, other):
    assert(check_type(other, (int, int)))
    assert(other[0]**2 % self.p == (self.D*other[1]**2 + 1) % self.p)
    return Point(self, *other)

class Point:
  def __init__(self, C, x, y):
    assert(isinstance(C, Curve))
    self.C = C
    self.x = x
    self.y = y
  def __repr__(self):
    return f"(0x{self.x:X}, 0x{self.y:X})"
  def __eq__(self, other):
    assert(self.C == other.C)
    return self.x == other.x and self.y == other.y
  def __add__(self, other):
    assert(self.C == other.C)
    x0, y0 = self.x, self.y
    x1, y1 = other.x, other.y
    return Point(self.C, (x0*x1 + self.C.D*y0*y1) % self.C.p, (x0*y1 + x1*y0) % self.C.p)
  def __rmul__(self, n):
    assert(check_type((n,), (int,)))
    P = self.C @ (1, 0)
    Q = self
    while n:
      if n & 1:
        P = P + Q
      Q = Q + Q
      n >>= 1
    return P
  def to_bytes(self):
    l = len(hex(self.C.p)[2:])
    return self.x.to_bytes(l, "big") + self.y.to_bytes(l, "big")

class Priv:
  def __init__(self, k, G):
    self.k = k
    self.G = G
    self.P = k*G
  def sign(self, m):
    r = random_int(16) % self.G.C.n
    R = r*self.G
    e = sha256_as_int(R.to_bytes() + self.P.to_bytes() + m) % self.G.C.n
    return (R, (r + self.k*e) % self.G.C.n)

C = Curve(0x34096DC6CE88B7D7CB09DE1FEC1EDF9B448D4BE9E341A9F6DC696EF4E4E213B3,
          0x3,
          0x34096DC6CE88B7D7CB09DE1FEC1EDF9B448D4BE9E341A9F6DC696EF4E4E213B2)
G = C @ (0x2, 0x1)
priv = Priv(0x0151EA0DB1A48D924206FB343A17ED36301744CB529AF45947F97E9EE88B9489, G)

import pwnlib.tubes

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

r.recvline()
r.recvuntil(b'nonce = ')
nonce = r.recvlineS(keepends = False)
nonce = bytes.fromhex(nonce)
sig = priv.sign(nonce)

r.recvuntil(b'sig = ')
r.sendline(f'{sig[0].x} {sig[0].y} {sig[1]}')

res = r.recvall()
if res.startswith(b'CTF{'):
  exit(0)
exit(1)
