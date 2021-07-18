#!/usr/bin/python3

# Copyright 2021 Google LLC
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

import os
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

flag = open('flag.txt').read()
INF = (1, 1, 0)

mod = 8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947
a = 6294860557973063227666421306476379324074715770622746227136910445450301914281276098027990968407983962691151853678563877834221834027439718238065725844264138
b = 3245789008328967059274849584342077916531909009637501918328323668736179176583263496463525128488282611559800773506973771797764811498834995234341530862286627 
n = 8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169
G = (5139617820728399941653175323358137352238277428061991823713659546881441331696699723004749024403291797641521696406798421624364096550661311227399430098134141,
     1798860115416690485862271986832828064808333512613833729548071279524320966991708554765227095605106785724406691559310536469721469398449016850588110200884962,
     5042518522433577951395875294780962682755843408950010956510838422057522452845550974098236475624683438351211176927595173916071040272153903968536756498306512)

def Double(p):
    x, y, z = p
    if z == 0 or y == 0:
        return INF
    ysqr = y * y % mod
    zsqr = z * z % mod
    s = 4 * x * ysqr % mod
    m = (3 * x * x + a * zsqr * zsqr) % mod
    x2 = (m * m - 2 * s) % mod
    y2 = (m * (s - x2) - 8 * ysqr * ysqr) % mod
    z2 = 2 * y * z % mod
    return x2, y2, z2

def Add(p, q):
    if p[2] == 0:
        return q
    if q[2] == 0:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1sqr = z1 * z1 % mod
    z2sqr = z2 * z2 % mod
    u1 = x1 * z2sqr % mod
    u2 = x2 * z1sqr % mod
    s1 = y1 * z2 * z2sqr % mod
    s2 = y2 * z1 * z1sqr % mod
    if u1 == u2:
        if s1 != s2:
            return INF
        else:
            return Double(p)
    h = u2 - u1 % mod
    hsqr = h * h % mod
    hcube = hsqr * h % mod
    r = s2 - s1 % mod
    t = u1 * hsqr % mod
    x3 = (r * r - hcube - 2 * t) % mod
    y3 = (r * (t - x3) - s1 * hcube) % mod
    z3 = h * z1 * z2 % mod
    return x3, y3, z3

def Multiply(p, x):
    if p == INF:
        return p
    res = INF
    while x:
        x, r = divmod(x, 2)
        if r:
            res = Add(res, p)
        p = Double(p)
    return res

def Transform(m, l):
    z = m
    shift = l - n.bit_length()
    if shift > 0:
        z >>= shift
    return z

def RNG(nbits, a, b):
    nbytes = nbits // 8
    B = os.urandom(nbytes)
    return a * sum([B[i] * b ** i for i in range(len(B))]) % 2**nbits

def Sign(msg, d):
    h = hashlib.sha512(msg)
    z = Transform(int.from_bytes(h.digest(), 'big'), h.digest_size*8)
    k = RNG(n.bit_length(), 16843009, 4294967296)
    x1, y1, z1 = Multiply(G, k)
    r = (x1 * pow(z1, -2, mod) % mod) % n
    s = pow(k, -1, n) * (z + r * d) % n
    return r, s

def Verify(msg, Q, r, s):
    h = hashlib.sha512(msg)
    z = Transform(int.from_bytes(h.digest(), 'big'), h.digest_size*8)
    u1 = z*pow(s, -1, n) % n
    u2 = r*pow(s, -1, n) % n
    x1, y1, z1 = Add(Multiply(G, u1), Multiply(Q, u2))
    return r == (x1 * pow(z1, -2, mod) % mod) % n

def Encrypt(plaintext, x):
    key = hashlib.sha256(str(x).encode()).digest()
    aes = algorithms.AES(key)
    encryptor = Cipher(aes, modes.ECB(), default_backend()).encryptor()
    padder = padding.PKCS7(aes.block_size).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

def Decrypt(ciphertext, x):
    key = hashlib.sha256(str(x).encode()).digest()
    aes = algorithms.AES(key)
    decryptor = Cipher(aes, modes.ECB(), default_backend()).decryptor()
    unpadder = padding.PKCS7(aes.block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize() 
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext 

# Alice and Bob have their keys:
da = RNG(n.bit_length(), 1, 256)
Qa = Multiply(G, da)
db = RNG(n.bit_length(), 1, 256)
Qb = Multiply(G, db)
x1a, y1a, z1a = Multiply(Qb, da)
ka = x1a * pow(z1a, -2, mod) % mod
x1b, y1b, z1b = Multiply(Qa, db)
kb = x1b * pow(z1b, -2, mod) % mod

# Alice sends message to Bob:
msga = b'Hello Bob.'
ra, sa = Sign(msga, da)
ca = Encrypt(msga, ka)
print('Alice -> Bob:', (ra, sa, int.from_bytes(ca, 'big')))

# Bob receives and verifies message:
recv_msg = Decrypt(ca, kb)
assert Verify(recv_msg, Qa, ra, sa)

# Bob sends message to Alice:
msgb = b'Hello Alice.'
rb, sb = Sign(msgb, db)
cb = Encrypt(msgb, kb)
print('Bob -> Alice:', (rb, sb, int.from_bytes(cb, 'big')))

# Alice receives and verifies message:
recv_msg = Decrypt(cb, ka)
assert Verify(recv_msg, Qb, rb, sb)

# Alice sends message to Bob:
msga = (f'Dinner tonight? What about Tapioca? Btw, here is the flag: {flag}').encode()
ra, sa = Sign(msga, da)
ca = Encrypt(msga, ka)
print('Alice -> Bob:', (ra, sa, int.from_bytes(ca, 'big')))

# Bob receives and verifies message:
recv_msg = Decrypt(ca, kb)
assert Verify(recv_msg, Qa, ra, sa)

# Bob sends message to Alice:
msgb = b'Dinner sounds good. Thanks for the flag.'
rb, sb = Sign(msgb, db)
cb = Encrypt(msgb, kb)
print('Bob -> Alice:', (rb, sb, int.from_bytes(cb, 'big')))

# Alice receives and verifies message:
recv_msg = Decrypt(cb, ka)
assert Verify(recv_msg, Qb, rb, sb)
