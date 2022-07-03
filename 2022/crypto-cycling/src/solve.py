#!/usr/bin/python3

# Copyright 2022 Google LLC
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

import sympy
from math import gcd

# A table of prime factors for 2**i-1 for commonly used field sizes. This
# is necessary since the factorization in this file just uses trial division.
MERSENNE_PRIME_FACTORS = {
    64: [3, 5, 17, 257, 641, 65537, 6700417],
    96: [3, 3, 5, 7, 13, 17, 97, 193, 241, 257, 673, 65537, 22253377],
    128: [3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721],
    160: [
        3, 5, 5, 11, 17, 31, 41, 257, 61681, 65537, 414721, 4278255361,
        44479210368001
    ],
    192: [
        3, 3, 5, 7, 13, 17, 97, 193, 241, 257, 641, 673, 65537, 6700417,
        22253377, 18446744069414584321
    ],
    224: [
        3, 5, 17, 29, 43, 113, 127, 257, 449, 2689, 5153, 65537, 15790321,
        183076097, 54410972897, 358429848460993
    ],
    255: [
        7, 31, 103, 151, 2143, 11119, 106591, 131071, 949111,
        9520972806333758431, 5702451577639775545838643151
    ],
    256: [
        3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
        59649589127497217, 5704689200685129054721
    ],
    384: [
        3, 3, 5, 7, 13, 17, 97, 193, 241, 257, 641, 673, 769, 65537, 274177,
        6700417, 22253377, 67280421310721, 18446744069414584321,
        442499826945303593556473164314770689
    ],
    448: [
        3, 5, 17, 29, 43, 113, 127, 257, 449, 641, 2689, 5153, 65537, 6700417,
        15790321, 183076097, 54410972897, 358429848460993,
        167773885276849215533569, 37414057161322375957408148834323969],
    512: [
        3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
        1238926361552897, 59649589127497217, 5704689200685129054721,
        93461639715357977769163558199606896584051237541638188580280321
    ],
    768: [
        # factors of 2**384 - 1
        3, 3, 5, 7, 13, 17, 97, 193, 241, 257, 641, 673, 769, 65537, 274177,
        6700417, 22253377, 67280421310721, 18446744069414584321,
        442499826945303593556473164314770689,
        # factors of 2**128 + 1
        59649589127497217, 5704689200685129054721,
        # factors of 2**256 - 2**128 + 1
        349621839326921795694385454593,
        331192380488114152600457428497953408512758882817
    ],
    1024: [
        3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
        1238926361552897, 59649589127497217, 5704689200685129054721,
        93461639715357977769163558199606896584051237541638188580280321, 2424833,
        7455602825647884208337395736200454918783366342657,
        741640062627530801524787141901937474059940781097519023905821316144415759504705008092818711693940737
    ],
    2048: [
        3, 5, 17, 257, 641, 65537, 274177, 6700417, 67280421310721,
        1238926361552897, 59649589127497217, 5704689200685129054721,
        93461639715357977769163558199606896584051237541638188580280321, 2424833,
        7455602825647884208337395736200454918783366342657, 45592577, 6487031809,
        4659775785220018543264560743076778192897,
        741640062627530801524787141901937474059940781097519023905821316144415759504705008092818711693940737,
        130439874405488189727484768796509903946608530841611892186895295776832416251471863574140227977573104895898783928842923844831149032913798729088601617946094119449010595906710130531906171018354491609619193912488538116080712299672322806217820753127014424577
    ]
}

def prod(f: list[int]) -> int:
  """Returns the product of a list of integers."""
  res = 1
  for p in f:
    res *= p
  return res

def divisors_from_factors(factors: list[int]) -> list[int]:
    """Computes a list of divisors of an integer given its factors.

    >>> divisors_from_factors([2,5])
    [1, 2, 5, 10]
    """
    res = {1}
    for f in factors:
      res |= set(x * f for x in res)
    return sorted(res)

class CycleLength:
  """Computes properties of RSA keys with a known cycle length.

  An instance of this class gives properties of RSA moduli n with
  the property that lambda(lambda(n)) divides max_cycle.
  The computation of these properties requires to know the factorization
  of max_cycle. Hence we use values for max_cycle for which the factorization
  is known. For example one can use max_cycle = 2 * (2^m - 1) and just
  look up the factorization of the Mersenne number 2^m - 1.

  This is code that is both used for generating challenges and for solving them.
  """

  def __init__(self, max_cycle_factors: list):
    """Defines the length of the cycle. 

    Args:
      max_cycle_factors: a list of prime factors of the maximal cycle
    """
    self.max_cycle_factors: list[int] = max_cycle_factors
    self.max_cycle = prod(max_cycle_factors)

    # A list of possible divisors of max_cycle
    self.max_cycle_divisors = divisors_from_factors(max_cycle_factors)

    # A list of primes with the property that r - 1 divides max_cycle.
    self.primes_ = None

  def primes(self) -> list:
    """Returns a list of primes r, such that r-1 divides self.max_cycle."""
    if self.primes_ is None:
      self.primes_ = [d + 1 for d in self.max_cycle_divisors
                      if sympy.isprime(d + 1)]
    return self.primes_

def solve(n: int, cycle_length: CycleLength, m0: int = 3, max_attempts: int = 10):
  for m in range(m0, m0 + max_attempts):
    for p in cycle_length.primes():
      m = pow(m, p, n)
      g = gcd(m - 1, n)
      if 1 < g < n:
        return g, n//g

def solve_challenge(n, cycle_length):
  res = solve(n, cycle_length)
  if res:
    p, q = res
    if 1 < p < n and 1 < q < n and p*q == n:
      return p, q 
  return None

e = 65537
n = 0x99efa9177387907eb3f74dc09a4d7a93abf6ceb7ee102c689ecd0998975cede29f3ca951feb5adfb9282879cc666e22dcafc07d7f89d762b9ad5532042c79060cdb022703d790421a7f6a76a50cceb635ad1b5d78510adf8c6ff9645a1b179e965358e10fe3dd5f82744773360270b6fa62d972d196a810e152f1285e0b8b26f5d54991d0539a13e655d752bd71963f822affc7a03e946cea2c4ef65bf94706f20b79d672e64e8faac45172c4130bfeca9bef71ed8c0c9e2aa0a1d6d47239960f90ef25b337255bac9c452cb019a44115b0437726a9adef10a028f1e1263c97c14a1d7cd58a8994832e764ffbfcc05ec8ed3269bb0569278eea0550548b552b1
ct = 0x339be515121dab503106cd190897382149e032a76a1ca0eec74f2c8c74560b00dffc0ad65ee4df4f47b2c9810d93e8579517692268c821c6724946438a9744a2a95510d529f0e0195a2660abd057d3f6a59df3a1c9a116f76d53900e2a715dfe5525228e832c02fd07b8dac0d488cca269e0dbb74047cf7a5e64a06a443f7d580ee28c5d41d5ede3604825eba31985e96575df2bcc2fefd0c77f2033c04008be9746a0935338434c16d5a68d1338eabdcf0170ac19a27ec832bf0a353934570abd48b1fe31bc9a4bb99428d1fbab726b284aec27522efb9527ddce1106ba6a480c65f9332c5b2a3c727a2cca6d6951b09c7c28ed0474fdc6a945076524877680

m = 1024
cycle_length = CycleLength([2] + MERSENNE_PRIME_FACTORS[m])
p, q = solve_challenge(n, cycle_length)
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
pt = pow(ct, d, n)
print(pt.to_bytes((pt.bit_length() + 7)//8, 'big').decode())
