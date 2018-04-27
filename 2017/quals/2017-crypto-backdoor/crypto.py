#!/usr/bin/python
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

def I(s):
  val = 0
  for i in range(len(s)):
    digit = ord(s[len(s) - i - 1])
    val <<= 8
    val |= digit
  return val

def Sn(i, length):
  s = ''
  while i != 0:
    digit = i & 0xff
    i >>= 8;
    s += chr(digit)
  return s

def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, p):
  a %= p
  g, x, y = egcd(a, p)
  if g != 1:
    raise Exception('No inverse exists for %d mod %d' % (a, p))
  else:
    return x % p

def add(a, b, p):
  if a == -1:
    return b
  if b == -1:
    return a
  x1, y1 = a
  x2, y2 = b
  x3 = ((x1*x2 - x1*y2 - x2*y1 + 2*y1*y2)*modinv(x1 + x2 - y1 - y2 - 1, p)) % p
  y3 = ((y1*y2)*modinv(x1 + x2 - y1 - y2 - 1, p)) % p
  return (x3, y3)

def double(a, p):
  return add(a, a, p)

def mul(m, g, p):
  r = -1
  while m != 0:
    if m & 1:
      r = add(r, g, p)
    m >>= 1
    g = double(g, p)
  return r

def encrypt(message, key):
  return message ^ key
