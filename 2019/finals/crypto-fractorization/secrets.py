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

import random
import gmpy2

flag = b'CTF{ju5t-A-cheap3r-w4y-t0-generate-pR1m3s}'
key = random.getrandbits(128).to_bytes(128 // 8, 'big')

def my_rsa_key_generator(nbits):
  pattern_size = 256 
  prime_size = nbits // 2

  pattern = gmpy2.mpz(random.getrandbits(pattern_size))
  pattern = pattern.bit_set(pattern_size - 1)
  pattern = pattern.bit_set(pattern_size - 2)
  p = pattern
  while p.bit_length() != prime_size:
    p = pattern + (p << pattern_size)

  # To make it harder we change MSB and LSB, so one shouldn't assume
  # are also patterns.
  msb = 8*6
  lsb = 8*10

  p = p & (2**(prime_size - msb) - 1)
  p = random.getrandbits(msb)*(2**(prime_size - msb)) + p
  p = p.bit_set(prime_size - 1)
  p = p.bit_set(prime_size - 2)

  p = p >> lsb 
  p = p << lsb
  p += random.getrandbits(lsb)
  p = gmpy2.next_prime(p)

  q = gmpy2.mpz(random.getrandbits(prime_size))
  q = q.bit_set(prime_size - 1)
  q = q.bit_set(prime_size - 2)
  q = gmpy2.next_prime(q)

  e = 0x10001
  n = p*q
  lcm = (p-1)*(q-1) // gmpy2.gcd(p-1, q-1)
  d = gmpy2.invert(e, lcm)

  return list(map(int, [n, e, d, p, q]))
