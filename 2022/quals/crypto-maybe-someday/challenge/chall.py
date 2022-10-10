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

from Crypto.Util.number import getPrime as get_prime
import math
import random
import os
import hashlib

# Suppose gcd(p, q) = 1. Find x such that
#   1. 0 <= x < p * q, and
#   2. x = a (mod p), and
#   3. x = b (mod q).
def crt(a, b, p, q):
    return (a*pow(q, -1, p)*q + b*pow(p, -1, q)*p) % (p*q)

def L(x, n):
    return (x-1) // n

class Paillier:
    def __init__(self):
        p = get_prime(1024)
        q = get_prime(1024)

        n = p * q
        λ = (p-1) * (q-1) // math.gcd(p-1, q-1) # lcm(p-1, q-1)
        g = random.randint(0, n-1)
        µ = pow(L(pow(g, λ, n**2), n), -1, n)

        self.n = n
        self.λ = λ
        self.g = g
        self.µ = µ

        self.p = p
        self.q = q

    # https://www.rfc-editor.org/rfc/rfc3447#section-7.2.1
    def pad(self, m):
        padding_size = 2048//8 - 3 - len(m)
        
        if padding_size < 8:
            raise Exception('message too long')

        random_padding = b'\0' * padding_size
        while b'\0' in random_padding:
            random_padding = os.urandom(padding_size)

        return b'\x00\x02' + random_padding + b'\x00' + m

    def unpad(self, m):
        if m[:2] != b'\x00\x02':
            raise Exception('decryption error')

        random_padding, m = m[2:].split(b'\x00', 1)

        if len(random_padding) < 8:
            raise Exception('decryption error')

        return m

    def public_key(self):
        return (self.n, self.g)

    def secret_key(self):
        return (self.λ, self.µ)

    def encrypt(self, m):
        g = self.g
        n = self.n

        m = self.pad(m)
        m = int.from_bytes(m, 'big')

        r = random.randint(0, n-1)
        c = pow(g, m, n**2) * pow(r, n, n**2) % n**2

        return c

    def decrypt(self, c):
        λ = self.λ
        µ = self.µ
        n = self.n

        m = L(pow(c, λ, n**2), n) * µ % n
        m = m.to_bytes(2048//8, 'big')

        return self.unpad(m)

    def fast_decrypt(self, c):
        λ = self.λ
        µ = self.µ
        n = self.n
        p = self.p
        q = self.q

        rp = pow(c, λ, p**2)
        rq = pow(c, λ, q**2)
        r = crt(rp, rq, p**2, q**2)
        m = L(r, n) * µ % n
        m = m.to_bytes(2048//8, 'big')

        return self.unpad(m)

def challenge(p):
    secret = os.urandom(2)
    secret = hashlib.sha512(secret).hexdigest().encode()

    c0 = p.encrypt(secret)
    print(f'{c0 = }')

    # # The secret has 16 bits of entropy.
    # # Hence 16 oracle calls should be sufficient, isn't it?
    # for _ in range(16):
    #     c = int(input())
    #     try:
    #         p.decrypt(c)
    #         print('😀')
    #     except:
    #         print('😡')

    # I decided to make it non-interactive to make this harder.
    # Good news: I'll give you 25% more oracle calls to compensate, anyways.
    cs = [int(input()) for _ in range(20)]
    for c in cs:
        try:
            p.fast_decrypt(c)
            print('😀')
        except:
            print('😡')

    guess = input().encode()

    if guess != secret: raise Exception('incorrect guess!')

def main():
    with open('/flag.txt', 'r') as f:
      flag = f.read()

    p = Paillier()
    n, g = p.public_key()
    print(f'{n = }')
    print(f'{g = }')

    try:
        # Once is happenstance. Twice is coincidence...
        # Sixteen times is a recovery of the pseudorandom number generator.
        for _ in range(16):
            challenge(p)
            print('💡')
        print(f'🏁 {flag}')
    except:
        print('👋')

if __name__ == '__main__':
    main()
