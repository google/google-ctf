# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import signal
import hashlib
import bcrypt
import os
from ecdsa.ecdsa import Signature
from ecdsa.curves import NIST256p

def tle_handler(*args):
    print('⏰')
    sys.exit(0)

def hash(message, salt):
    h = bcrypt.hashpw(message, salt)
    _salt, h = h[:29], h[29:]
    assert salt == _salt
    return h

def recover_public_key(message, signature):
    hash = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    r, s = [int.from_bytes(signature[i:i+32], 'big') for i in range(0, 64, 32)]
    v = signature[64]

    public_keys = Signature(r, s).recover_public_keys(hash, NIST256p.generator)
    x = public_keys[v].point.x()
    return int.to_bytes(x, 32, 'big')

SALT_FOR_NODE    = bcrypt.gensalt(4)
SALT_FOR_VALUE   = bcrypt.gensalt(4)
EMPTY_NODE_HASH  = hash(b'', SALT_FOR_NODE)
EMPTY_VALUE_HASH = hash(b'', SALT_FOR_VALUE)


class RadixTree:
    def __init__(self):
        self.value = None
        self.left_subtree = None
        self.right_subtree = None
        self.cached_hash = None

    def _set(self, hash_key, value, depth=0):
        self.cached_hash = None

        if depth == 256:
            self.value = value
            return

        if hash_key & 1 == 0:
            if self.left_subtree is None:
                self.left_subtree = RadixTree()
            self.left_subtree._set(hash_key>>1, value, depth+1)
        else:
            if self.right_subtree is None:
                self.right_subtree = RadixTree()
            self.right_subtree._set(hash_key>>1, value, depth+1)

    def set(self, key, value):
        hash_key = hashlib.sha256(key).digest()
        hash_key = int.from_bytes(hash_key, 'big')
        self._set(hash_key, value)

    def _get(self, hash_key, depth=0):
        if depth == 256 and self.value is not None:
            return self.value

        if hash_key & 1 == 0 and self.left_subtree is not None:
            return self.left_subtree._get(hash_key>>1, depth+1)
        elif hash_key & 1 == 1 and self.right_subtree is not None:
            return self.right_subtree._get(hash_key>>1, depth+1)
        return 0

    def get(self, key):
        hash_key = hashlib.sha256(key).digest()
        hash_key = int.from_bytes(hash_key, 'big')
        return self._get(hash_key)

    # Show that "tree[key] = value"
    # Proof format: [value (8 bytes)][hash (31 bytes)][hash (31 bytes)]...[hash (31 bytes)]
    def verify(self, key, proof):
        hash_key = hashlib.sha256(key).digest()
        hash_key = int.from_bytes(hash_key, 'big')

        # Leaf node hash
        current_hash = hash(b':::'.join([
            EMPTY_NODE_HASH,
            EMPTY_NODE_HASH,
            hash(proof[0:8], SALT_FOR_VALUE)
        ]), SALT_FOR_NODE)

        for bit, i in zip(range(256-1, -1, -1), range(8, len(proof), 31)):
            proof_block = proof[i:i+31]
            if hash_key & (1 << bit) == 0:
                message = b':::'.join([current_hash, proof_block, EMPTY_VALUE_HASH])
                current_hash = hash(message, SALT_FOR_NODE)
            else:
                message = b':::'.join([proof_block, current_hash, EMPTY_VALUE_HASH])
                current_hash = hash(message, SALT_FOR_NODE)

        if current_hash != self.hash(): raise Exception('invalid proof')
        return int.from_bytes(proof[0:8], 'big')

    def hash(self):
        if self.cached_hash is not None:
            return self.cached_hash
        

        hash_material = []

        if self.left_subtree is not None:  hash_material.append(self.left_subtree.hash())
        else:                              hash_material.append(EMPTY_NODE_HASH)
    
        if self.right_subtree is not None: hash_material.append(self.right_subtree.hash())
        else:                              hash_material.append(EMPTY_NODE_HASH)
    
        if self.value is not None:         hash_material.append(hash(int.to_bytes(self.value, 8, 'big'), SALT_FOR_VALUE))
        else:                              hash_material.append(EMPTY_VALUE_HASH)

        message = b':::'.join(hash_material)
        self.cached_hash = hash(message, SALT_FOR_NODE)

        return self.cached_hash


def main():
    # The clock is ticking!
    signal.signal(signal.SIGALRM, tle_handler)
    signal.alarm(60)

    tree = RadixTree()
    with open('/flag.txt', 'r') as f:
      flag = f.read()

    print(f'🧂 {SALT_FOR_NODE.decode()}')
    print(f'🧂 {SALT_FOR_VALUE.decode()}')

    player_local_amount = 10**9

    while True:
        cmd, *args = input('🤖 ').strip().split(' ')
        if cmd == 'deposit':
            amount, public_key = int(args[0]), bytes.fromhex(args[1])
            if amount <= 0: raise Exception('invalid amount')
            if amount > player_local_amount: raise Exception('invalid amount')

            player_remote_amount = tree.get(public_key)

            player_local_amount -= amount
            tree.set(public_key, player_remote_amount + amount)

        elif cmd == 'withdraw':
            amount, signature, proof = int(args[0]), bytes.fromhex(args[1]), bytes.fromhex(args[2])
            if amount <= 0: raise Exception('invalid amount')
            public_key = recover_public_key(proof, signature)

            player_remote_amount = tree.verify(public_key, proof)
            if amount > player_remote_amount: raise Exception('invalid amount')

            player_local_amount += amount
            tree.set(public_key, player_remote_amount - amount)

        elif cmd == 'flag':
            if player_local_amount < 10**18: raise Exception('please earn more')
            print(f'🏁 {flag}')
            sys.exit(0)


if __name__ == '__main__':
    main()
