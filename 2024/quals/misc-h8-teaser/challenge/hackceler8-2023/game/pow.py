# Copyright 2024 Google LLC
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

# Taken from https://github.com/google/kctf/blob/v1/docker-images/challenge/pow.py

import base64
import os
import secrets
import socket
import sys
import hashlib

try:
    import gmpy2
    HAVE_GMP = True
except ImportError:
    HAVE_GMP = False
    sys.stderr.write("[NOTICE] Running 10x slower, gotta go fast? pip3 install gmpy2\n")

VERSION = 's'
MODULUS = 2**1279-1
CHALSIZE = 2**128

def python_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for i in range(diff):
        x = pow(x, exponent, p) ^ 1
    return x

def python_sloth_square(y, diff, p):
    for i in range(diff):
        y = pow(y ^ 1, 2, p)
    return y

def gmpy_sloth_root(x, diff, p):
    exponent = (p + 1) // 4
    for i in range(diff):
        x = gmpy2.powmod(x, exponent, p).bit_flip(0)
    return int(x)

def gmpy_sloth_square(y, diff, p):
    y = gmpy2.mpz(y)
    for i in range(diff):
        y = gmpy2.powmod(y.bit_flip(0), 2, p)
    return int(y)

def sloth_root(x, diff, p):
    if HAVE_GMP:
        return gmpy_sloth_root(x, diff, p)
    else:
        return python_sloth_root(x, diff, p)

def sloth_square(x, diff, p):
    if HAVE_GMP:
        return gmpy_sloth_square(x, diff, p)
    else:
        return python_sloth_square(x, diff, p)

def encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, 'big')), 'utf-8')

def decode_number(enc):
    return int.from_bytes(base64.b64decode(bytes(enc, 'utf-8')), 'big')

def decode_challenge(enc):
    dec = enc.split('.')
    if dec[0] != VERSION:
        raise Exception('Unknown challenge version')
    return list(map(decode_number, dec[1:]))

def encode_challenge(arr):
    return '.'.join([VERSION] + list(map(encode_number, arr)))

def get_challenge(diff):
    x = secrets.randbelow(CHALSIZE)
    return encode_challenge([diff, x])

def solve_challenge(chal):
    [diff, x] = decode_challenge(chal)
    y = sloth_root(x, diff, MODULUS)
    return encode_challenge([y])

def verify_challenge(chal, sol):
    [diff, x] = decode_challenge(chal)
    [y] = decode_challenge(sol)
    res = sloth_square(y, diff, MODULUS)
    return (x == res) or (MODULUS - x == res)
