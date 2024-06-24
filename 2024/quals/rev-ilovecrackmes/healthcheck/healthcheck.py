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

import math
import random

import pwnlib.tubes


class Paillier:

  def __init__(self, g):
    self.g = g
    self.n = g - 1
    self.nsquared = self.n**2

  def find_r(self):
    while True:
      r = random.randint(1, self.n-1)
      if math.gcd(r, self.n) == 1:
        return r

  def encrypt(self, x):
    r = self.find_r()
    return (
        pow(self.g, x, self.nsquared) * pow(r, self.n, self.nsquared)
    ) % self.nsquared

  def mul(self, a, p):
    return pow(a, p, self.nsquared)

  def add(self, a, b):
    return (a * b) % self.nsquared


def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

data = r.recvuntil(b'>')[:-1].strip()

g, x_enc =  map(lambda x: int(x, 16), data.split(b':'))
p = Paillier(g)
y = x_enc

for c in b'ilovecrackmes':
  c_enc = p.encrypt(c)
  y = p.add(p.mul(y, 256), c_enc)


r.sendline(bytes(hex(y)[2:], 'utf-8'))


print(r.recvuntil(b'CTF{'))
print(r.recvuntil(b'}'))

exit(0)
