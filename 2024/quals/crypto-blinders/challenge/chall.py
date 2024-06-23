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

from ecdsa.curves import NIST256p
from ecdsa.numbertheory import jacobi, square_root_mod_prime
from ecdsa.ellipticcurve import Point
from Crypto.Random import random
import hashlib

curve = NIST256p.curve

def H(id):
    a, b, p = curve.a(), curve.b(), curve.p()

    hash = hashlib.sha256(f'id={id}'.encode()).digest()
    x = int.from_bytes(hash, 'big')

    while True:
        y2 = (x**3 + a*x + b) % p
        if jacobi(y2, p) == 1: break
        x += 1

    y = square_root_mod_prime(y2, p)
    return Point(curve, x, y)

# Implements Blinders, a private set membership protocol.
class BlindersServer:
    def __init__(self, S):
        self.S = S
    
    def handle(self, client_eid):
        # 2.1. Generate a random secret key k
        k = random.randrange(0, NIST256p.order)
        # Compute eid1 = H(id1)^K, ..., eidn = H(idn)^K
        eids = [H(id) * k for id in self.S]
        # Compute doubly-encrypted identifier deid = eid^K
        deid = client_eid * k
        # Return (eid1, ..., eidn) and deid to P1
        return eids, deid

def challenge():
    # S = {0, 1, ..., 255} \ {x} for some 0 <= x < 256
    S = list(range(256))
    S.remove(random.getrandbits(8))
    server = BlindersServer(S)

    for _ in range(3):
        operation, *params = input().split()
        if operation == 'handle':
            client_eid = Point(curve, int(params[0]), int(params[1]))
            eids, deid = server.handle(client_eid)
            print([(eid.x(), eid.y()) for eid in eids])
            print((deid.x(), deid.y()))
        elif operation == 'submit':
            client_S_hash = bytes.fromhex(params[0])
            S_hash = hashlib.sha256(','.join(map(str, server.S)).encode()).digest()
            return client_S_hash == S_hash
        else:
            return False

if __name__ == '__main__':
    with open('/flag.txt', 'r') as f:
        FLAG = f.read().strip()

    # Convince me 16 times and I will give you the flag :)
    for _ in range(16):
        if challenge():
            print('OK!')
        else:
            print('Nope.')
            break
    else:
        print(FLAG)