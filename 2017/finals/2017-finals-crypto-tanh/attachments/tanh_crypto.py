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

# a :+: b = tanh(arctanh(a) + arctanh(b)) = (a + b)/(ab + 1)

import math
import hashlib
from os import urandom

def randBytes(numBytes):
  return I(urandom(numBytes))

def I(s):
  """Convert a binary string to an int."""
  val = 0
  for i in range(len(s)):
    digit = ord(s[len(s) - i - 1])
    val <<= 8
    val |= digit
  return val

def Sn(i, length):
  """Convert an int to a binary string of a fixed length."""
  s = ''
  while i != 0:
    digit = i & 0xff
    i >>= 8
    s += chr(digit)
  if len(s) > length:
    raise Exception("Integer too big to fit")
  while len(s) < length:
    s += chr(0)
  return s

def S(i):
  """Convert an int to a binary string wide enough to hold it."""
  s = ''
  while i != 0:
    digit = i & 0xff
    i >>= 8
    s += chr(digit)
  return s

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    a %= m
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse for %d does not exist mod %d' % (a, m))
    else:
        return x % m

def add(a, b, p):
    return  (a + b)*modinv(a*b + 1, p) % p

def scalarMult(g, k, p):
    """Multiply g by the scalar k, mod p."""
    r = 0
    val = g
    while k != 0:
        if k & 1:
            r = add(r, val, p)
        k >>= 1
        val = add(val, val, p)
    return r

def expand(secret, numBytes):
    bytes = b""
    m = hashlib.sha256()
    digest_size = hashlib.sha256().digest_size
    for i in range((numBytes + digest_size - 1) // digest_size):
        bytes += hashlib.sha256(Sn(i, 4) + S(secret)).digest()
        m.digest()
    return bytes[0:numBytes]

def encrypt(pubkey, message, g, p):
    length = int(math.log(p, 256)) + 1
    randSecret = randBytes(length) % p
    myPubkey = scalarMult(g, randSecret, p)
    sharedSecret = scalarMult(pubkey, randSecret, p)
    mask = expand(sharedSecret, len(message))
    return Sn(myPubkey, length) + Sn(I(mask) ^ I(message), len(message))

def decrypt(secret, encMessage, g, p):
    length = int(math.log(p, 256)) + 1
    theirPubkey = I(encMessage[0:length])
    encMessage = encMessage[length:]
    sharedSecret = scalarMult(theirPubkey, secret, p)
    mask = expand(sharedSecret, len(encMessage))
    return Sn(I(mask) ^ I(encMessage), len(encMessage))

encMessage = S(0xebcb30396ef4b2990bb4628c82d34c518fd19934920838c56687a663ee2ccd9e8bc52269eae45a03b2d6)

p = 11089258196146291747062674821937
g = 123456789
pubkey = 4946333654980525705876548945973

# Uncomment to regenerate public key.
# secret = ...
# pubkey = scalarMult(g, secret, p)
# print "pubkey =", pubkey

# Uncomment this to encrypt the message.
# message = "CTF{...
# encMessage = encrypt(pubkey, message, g, p)
# print "encMessage = %x" % I(encMessage)

# Uncomment this to decrypt the message.
# secret = ...
# print decrypt(secret, encMessage, g, p)
