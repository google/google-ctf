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
import gmpy2

a = 0xe64a5f84e2762be5
chunk_size = 64

def gen_prime(bits):
  s = random.getrandbits(chunk_size)

  while True:
    s |= 0xc000000000000001
    p = 0
    for _ in range(bits // chunk_size):
      p = (p << chunk_size) + s
      s = a * s % 2**chunk_size
    if gmpy2.is_prime(p):
      return p

n = gen_prime(1024) * gen_prime(1024)
e = 65537
flag = open("flag.txt", "rb").read()
print('n =', hex(n))
print('e =', hex(e))
print('c =', hex(pow(bytes_to_long(flag), e, n)))
