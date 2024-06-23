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

import hashlib
import json
from math import gcd

# param.py is created by generated.py. Run that locally to generate parameters :)
from param import n as n0, c as c0

def hash(s):
    m = b''
    for si in s:
        sib = int.to_bytes(si, (int(si).bit_length()+7)//8, 'big')
        sil = int.to_bytes(len(sib), 2, 'big')
        m += sil
        m += sib
    return hashlib.md5(m).digest()

def verify(n, c, proof):
    s = proof.get('s')
    z = proof.get('z')
    h = int.from_bytes(hash(s), 'big')
    b = [(h>>i)&1 for i in range(127, -1, -1)]
    if len(s) != 128: return False
    if len(z) != 128: return False
    if len(b) != 128: return False

    for si, zi, bi in zip(s, z, b):
        if gcd(si, n) != 1: return False
        if pow(zi, 2, n) != si * pow(c, bi, n) % n: return False
    return True


def main():
    print('Send me your proof.')
    proof = json.loads(input('> '))
    n = proof.get('n')
    c = proof.get('c')

    if not verify(n, c, proof):
        print('BAD.')
    elif n != n0 or c != c0:
        print("I am convinced that you have m such that m^2 = c (mod n). What's next?")
    else:
        with open('message.txt', 'r') as f:
            message = f.read().strip()
        print(message)


if __name__ == '__main__':
    main()
