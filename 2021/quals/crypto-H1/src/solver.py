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

from sage.all import *
import fpylll
import gmpy2
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

mod = 8948962207650232551656602815159153422162609644098354511344597187200057010413552439917934304191956942765446530386427345937963894309923928536070534607816947
a = 6294860557973063227666421306476379324074715770622746227136910445450301914281276098027990968407983962691151853678563877834221834027439718238065725844264138
b = 3245789008328967059274849584342077916531909009637501918328323668736179176583263496463525128488282611559800773506973771797764811498834995234341530862286627 
n = 8948962207650232551656602815159153422162609644098354511344597187200057010413418528378981730643524959857451398370029280583094215613882043973354392115544169
G = (5139617820728399941653175323358137352238277428061991823713659546881441331696699723004749024403291797641521696406798421624364096550661311227399430098134141,
     1798860115416690485862271986832828064808333512613833729548071279524320966991708554765227095605106785724406691559310536469721469398449016850588110200884962,
     5042518522433577951395875294780962682755843408950010956510838422057522452845550974098236475624683438351211176927595173916071040272153903968536756498306512)
E = EllipticCurve(Zmod(mod), [a, b])
# Converts to Affine:
G = E((G[0]*gmpy2.invert(G[2], mod)**2, G[1]*gmpy2.invert(G[2], mod)**3))

def lll_reduce(matrix):
    tmp = [[int(v) for v in row] for row in matrix]
    m = fpylll.IntegerMatrix.from_matrix(tmp)
    reduced = fpylll.LLL.reduction(m)
    res = [[0] * reduced.ncols for _ in range(reduced.nrows)]
    reduced.to_matrix(res)
    return res

def HNPProblem(a, b, w, p, basis):
    words = len(basis)
    # size of the lattice
    lat_size = 2 * words + 2
    lat = [[0] * lat_size for i in range(lat_size)]
    for j, v in enumerate(basis):
        lat[j][j] = 1
        lat[j][-1] = v * a % p
        lat[j + words][j + words] = 1
        lat[j + words][-1] = v * b % p
    lat[-2][-2] = 256
    lat[-2][-1] = w
    lat[-1][-1] = p
    reduced = lll_reduce(lat)
    for row in reduced:
        k1 = abs(sum(v * w for v, w in zip(basis, row[:words])))
        k2 = abs(sum(v * w for v, w in zip(basis, row[words:2 * words])))
        if (k1 * a + k2 * b - w) % p == 0:
            yield k1, k2

def Guesses(r1, s1, h1, r2, s2, h2, n):
    a = r2 * s1 % n
    b = -r1 * s2 % n
    w = (r2 * h1 - r1 * h2) % n
    basis = [0x1010101 << j for j in range(0, n.bit_length(), 32)]
    guesses = set()
    for k1, k2 in HNPProblem(a, b, w, n, basis):
        r1inv = int(gmpy2.invert(r1, n))
        x1 = (s1 * k1 - h1) * r1inv % n
        guesses.add(x1)
    return sorted(guesses)

def GetSigPKs(r, s, z):
    ri = gmpy2.invert(r, n)
    ri_z = ri * z % n
    ri_s = ri * s % n
    ri_z_g = ri_z * G
    pks = []
    for rr in range(r, mod, n):
        r_points = E.lift_x(Integer(rr), True)
        for r_point in r_points:
            pks.append(ri_s * r_point - ri_z_g)
    return pks

def Transform(m, l):
    z = m
    shift = l - n.bit_length()
    if shift > 0:
        z >>= shift
    return z

def Decrypt(ciphertext, x):
    key = hashlib.sha256(str(x).encode()).digest()
    aes = algorithms.AES(key)
    decryptor = Cipher(aes, modes.ECB(), default_backend()).decryptor()
    unpadder = padding.PKCS7(aes.block_size).unpadder()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize() 
    plaintext = unpadder.update(decrypted_data) + unpadder.finalize()
    return plaintext

msgb1 = b'Hello Alice.'
msgb2 = b'Dinner sounds good. Thanks for the flag.'
hb1 = hashlib.sha512(msgb1)
zb1 = Transform(int.from_bytes(hb1.digest(), 'big'), hb1.digest_size*8)
hb2 = hashlib.sha512(msgb2)
zb2 = Transform(int.from_bytes(hb2.digest(), 'big'), hb2.digest_size*8)

msga1 = b'Hello Bob.'
ha1 = hashlib.sha512(msga1)
za1 = Transform(int.from_bytes(ha1.digest(), 'big'), ha1.digest_size*8)

lines = open("output.txt").readlines()
ra1, sa1, ca1 = list(map(int, lines[0][15:-2].split(", ")))
rb1, sb1, cb1 = list(map(int, lines[1][15:-2].split(", ")))
ra2, sa2, ca2 = list(map(int, lines[2][15:-2].split(", ")))
rb2, sb2, cb2 = list(map(int, lines[3][15:-2].split(", ")))

db = Guesses(rb1, sb1, zb1, rb2, sb2, zb2, n)[0]
print(db % n)
Qas = GetSigPKs(ra1, sa1, za1)
for Qa in Qas:
    x, y = (db * Qa).xy()
    try:
        print(Decrypt(int.to_bytes(ca2, math.ceil(ca2.bit_length() / 8), 'big'), x))
    except:
        pass
