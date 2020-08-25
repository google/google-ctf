#!/usr/bin/python3 -u
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

import random
from Crypto.Util.number import *
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import binascii

def generate_prime(prime_len):
  bits_len = 180
  while True:
    bits = random.getrandbits(bits_len)
    idxs = random.sample(list(range(1, prime_len-2)), bits_len)
    p = 1 | 2**(prime_len - 1) | 2**(prime_len - 2)
    for i in range(bits_len):
      p += (bits >> i & 1)*2**idxs[i]
    if isPrime(p):
      return p

key = None
flag = open("flag.txt", "rb").read()

print("Welcome to my Prime Obsession. Tell me what do you want.\n")
while True:
    print("[1] Generate key")
    print("[2] Get Encrypted flag")
    print("[3] Exit")
    opt = int(input(">>> "))
    if opt == 1:
        p = generate_prime(1024)
        q = generate_prime(1024)
        e = 65537
        n = p*q
        key = RSA.construct((n, e))
        print(key.exportKey('PEM').decode())
    if opt == 2:
        if not key:
            print("No key generated :/")
        else:
            cipher = PKCS1_OAEP.new(key)
            print(binascii.hexlify(cipher.encrypt(flag)).decode())
    if opt == 3:
        print("You are not obsessed enough :/")
        break
    print("\n")
