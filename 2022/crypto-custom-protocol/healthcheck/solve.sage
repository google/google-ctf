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

import time
import itertools
from pwn import *

def unpad(padded_data: bytes, block_size: int) -> bytes:
    #Remove ISO/IEC 7816-4 padding.
    pdata_len = len(padded_data)
    padding_len = pdata_len - padded_data.rfind(b'\x80')
    return padded_data[:-padding_len]

def int2bytes(int_val: int) -> bytes:
  int_val = int(int_val)
  return int_val.to_bytes((int_val.bit_length() + 7) // 8, 'big')

def multivariate(f, N, bounds, m=4):
    fz = f/f.coefficients()[0]
    fz = fz.change_ring(ZZ)
    xs = fz.variables()
    n = len(xs)
    t = max(1, floor((1 - (0.5)**(1/n))*m))

    # Compute polynomials. Each polynomial adds a new monomial.
    pols = []
    mons = []
    all_idxs = list(itertools.product(range(m + 1), repeat = n - 1))
    for k in range(m + 1):
        idxs = [idx for idx in all_idxs if sum(idx) <= m-k]
        g = fz**k * N**max(t-k, 0)
        mon = xs[0]**k
        mul = bounds[0]**k
        for ijs in idxs:
            t1 = 1
            for i in range(1, n):
                t1 *= xs[i]**ijs[i-1]
            pols.append(t1*g)
            mons.append(t1*mon)
    dim = len(pols)
    # create the lattice using the coefficients
    L = Matrix(ZZ, dim)
    params = [xs[i]*bounds[i] for i in range(n)]
    for i in range(len(pols)):
        L[i, 0] = pols[i].constant_coefficient()
        pol = pols[i](*params)
        for j in range(1, i+1):
            L[i, j] = pol.monomial_coefficient(mons[j])

    L = L.LLL()
    for i in range(L.nrows()):
        for j in range(L.ncols()):
            L[i, j] //= mons[j](*bounds)

    monomials = vector(mons)
    H = Sequence([row*monomials for row in L], fz.parent().change_ring(QQ))
    I = H.ideal()
    while I.dimension() != 0:
        H.pop()
        print("%d..." % len(H))
        if len(H) <= n:
            return None
        I = H.ideal()
    for root in I.variety(ring=ZZ):
        return tuple(R(root[var]) for var in f.variables())
    return None

proc = remote("localhost", 1337)
#proc = remote("custom-protocol.2022.ctfcompetition.com", 1337)
res = proc.recvuntil(b">>> ")
proc.sendline(b"1")
e = int(proc.recvline().split(b" = ")[1], 16)
n = int(proc.recvline().split(b" = ")[1], 16)

res = proc.recvuntil(b">>> ")
proc.sendline(b"2")
enc = int(proc.recvline().split(b" = ")[1], 16)

print(e)
print(n)
print(enc)

# Look for a faulty signature:
print("Looking for faulty signature...")
while True:
    res = proc.recvuntil(b">>> ")
    proc.sendline(b"4")
    sig = int(proc.recvline().split(b" = ")[1], 16)
    dec = pow(sig, e, n)
    if b'My crypto protocol' not in int2bytes(dec):
        print("Found!")
        proc.close()
        break

# Partial information:
t = 0xa194d792063727970746f2070726f746f636f6c2076302e302e311210000000000000000000000000000000001a8501466f722074686973207369676e696e67206f6964204920616d206e6f7420737572652c20627574204920776f756c6420677565737320736f6d657468696e6720696e206265747765656e20312e322e3834302e3131333534392e322e3720616e6420312e322e3834302e3131333534392e312e312e3520706c7573206e6f6e6365203a292e221400000000000000000000000000000000000000002a8801466f722074686973207369676e696e6720616c676f726974686d204920616d206e6f7420737572652c20627574204920776f756c6420677565737320736f6d657468696e6720696e206265747765656e20686d6163576974685348413120616e6420736861312d776974682d7273612d7369676e617475726520706c7573206e6f6e6365203a292e3214000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

# Trivariate:
R.<x, y, z> = PolynomialRing(Zmod(n))
unknown_bits_x = 128
unknown_bits_y = 160 
unknown_bits_z = 160

X = 2^unknown_bits_x
Y = 2^unknown_bits_y
Z = 2^unknown_bits_z

aa = t - int(pow(sig, e, n))
bb = 2**3736
cc = 2**2472
dd = 2**1184

pol = aa + bb*x + cc*y + dd*z
now = time.time()
roots = multivariate(pol, n, [X, Y, Z], m=5)
print(time.time() - now)
print(roots)
hmac_key, salt, digest = roots
p = int(gcd(int(aa + bb*hmac_key + cc*salt + dd*digest), n))
q = n//p
assert n == p*q and 1 < p < n and 1 < q < n

d = inverse_mod(e, (p-1)*(q-1))
plaintext = unpad(int2bytes(pow(enc, d, n)), n.bit_length()//8)
print(plaintext[plaintext.index(b'CTF{'):])
