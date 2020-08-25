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

import gmpy2
import sympy
from Crypto.Util.number import *

n = 0xab802dca026b18251449baece42ba2162bf1f8f5dda60da5f8baef3e5dd49d155c1701a21c2bd5dfee142fd3a240f429878c8d4402f5c4c7f4bc630c74a4d263db3674669a18c9a7f5018c2f32cb4732acf448c95de86fcd6f312287cebff378125f12458932722ca2f1a891f319ec672da65ea03d0e74e7b601a04435598e2994423362ec605ef5968456970cb367f6b6e55f9d713d82f89aca0b633e7643ddb0ec263dc29f0946cfc28ccbf8e65c2da1b67b18a3fbc8cee3305a25841dfa31990f9aab219c85a2149e51dff2ab7e0989a50d988ca9ccdce34892eb27686fa985f96061620e6902e42bdd00d2768b14a9eb39b3feee51e80273d3d4255f6b19
e = 0x10001
c = 0x6a12d56e26e460f456102c83c68b5cf355b2e57d5b176b32658d07619ce8e542d927bbea12fb8f90d7a1922fe68077af0f3794bfd26e7d560031c7c9238198685ad9ef1ac1966da39936b33c7bb00bdb13bec27b23f87028e99fdea0fbee4df721fd487d491e9d3087e986a79106f9d6f5431522270200c5d545d19df446dee6baa3051be6332ad7e4e6f44260b1594ec8a588c0450bcc8f23abb0121bcabf7551fd0ec11cd61c55ea89ae5d9bcc91f46b39d84f808562a42bb87a8854373b234e71fe6688021672c271c22aad0887304f7dd2b5f77136271a571591c48f438e6f1c08ed65d0088da562e0d8ae2dadd1234e72a40141429f5746d2d41452d916

a = 0xe64a5f84e2762be5
chunk_size = 64

a_inv = gmpy2.invert(a, 2**chunk_size)
ab = n % 2**chunk_size
abg = a_inv * ab * 2 % 2 ** chunk_size
xab = (n - (abg << chunk_size)) % 2**(chunk_size*2)

for x in sympy.divisors(xab):
  if x.bit_length() <= chunk_size and xab // x <= x:
    print('testing', hex(x))
    chunks = n.bit_length() // (chunk_size*2)
    p = 0
    a = x
    for i in range(chunks):
      p += a << (i * chunk_size)
      a = a * a_inv % 2**chunk_size
    if n % p == 0:
      print('factor found:', hex(p))
      q = n//p
      phi = (p-1)*(q-1)
      assert gmpy2.gcd(e, phi) == 1
      d = gmpy2.invert(e, phi)
      print(long_to_bytes(pow(c, d, n)))
      break 
