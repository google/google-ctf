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

import ast
import socket
from Crypto.Random import random
import hashlib
from rich.progress import track
from ecdsa.curves import NIST256p
from ecdsa.numbertheory import jacobi, square_root_mod_prime
from ecdsa.ellipticcurve import Point

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

class BlindersAPI:
    def __init__(self, host, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.settimeout(10)
        self.s = s

    def recvline(self):
        output = []
        while True:
            c = self.s.recv(1)
            if c == b'' or c == b'\n': break
            output.append(c)
        return b''.join(output)

    def handle(self, eid):
        self.s.send(f'handle {eid.x()} {eid.y()}\n'.encode())
        eids = ast.literal_eval(self.recvline().decode())
        deid = ast.literal_eval(self.recvline().decode())
        return [Point(curve, *eid) for eid in eids], Point(curve, *deid)

    def submit(self, S):
        sorted_S = sorted(S)
        hash = hashlib.sha256(','.join(map(str, sorted_S)).encode()).hexdigest()
        self.s.send(f'submit {hash}\n'.encode())
        return self.recvline().decode()
    
    def final(self):
        return self.recvline().decode()

# Implements the client side of Blinders
class BlindersClient:
    def __init__(self, api):
        self.api = api

    def query(self, id):
        # 1.1. Generate a random key R
        r = random.randrange(q)
        r_inverse = int(pow(r, -1, q))
        # 1.2. Compute encrypted identified eid = H(id)^R
        eid = H(id) * r
        # 1.3. Send eid to P2
        server_eids, deid = self.api.handle(eid)
        
        # 3.1. Compute eid' = deid^(1/R)
        new_eid = deid * r_inverse
        # If eid' = eidi for any i = 1, ..., n, return S = {id}
        # Otherwise return S = {}.
        return new_eid in server_eids
    
    def submit(self, S: list[str]):
        return self.api.submit(S)

    def final(self) -> str:
        return self.api.final()


def attempt(api):
    eid = sum([H(j + 0) for j in range(0, 256, 2)], start=NIST256p.generator*0)
    server_eids_0, deid_0 = api.handle(eid)

    eid = sum([H(j + 1) for j in range(0, 256, 2)], start=NIST256p.generator*0)
    server_eids_1, deid_1 = api.handle(eid)

    for x in range(256):
        S = list(range(256))
        S.remove(x)

        if x % 2 == 1:
            # an odd number is removed, i.e., [0, 2, ..., 254] ⊆ S
            # idxs are the indices of [0, 2, ..., 254] in S
            idxs = [S.index(x) for x in range(0, 256, 2)]
            if sum([server_eids_0[idx] for idx in idxs], start=NIST256p.generator*0) == deid_0: break
        else:
            # an even number is removed, i.e., [1, 3, ..., 255] ⊆ S
            # idxs are the indices of [1, 3, ..., 255] in S
            idxs = [S.index(x) for x in range(1, 256, 2)]
            if sum([server_eids_1[idx] for idx in idxs], start=NIST256p.generator*0) == deid_1: break
    else:
        assert False, 'skill issue'

    assert api.submit(S) == 'OK!'


def main():
    api = BlindersAPI('localhost', 1337)
    api.recvline()

    for _ in track(range(16)): attempt(api)

    print(api.final())


if __name__ == '__main__':
    main()