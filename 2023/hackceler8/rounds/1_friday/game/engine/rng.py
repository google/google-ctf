# Copyright 2023 Google LLC
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

import logging
import random
import hashlib
import xxhash


class RngSystem:
    def __init__(self):
        # Fixed rng
        self.frng = random.Random(42)
        # Seeded at startup
        self.prng = random.Random(42)

        self.hash = ''
        self.dump_as_hash()

    def seed(self, seed):
        random.seed(seed)
        self.prng.seed(seed)

    def tick(self, raw_pressed_keys, tick):
        self.frng.getrandbits(32)
        self.dump_as_hash()

    def get(self, rng_type):
        if rng_type in {'frng', 'prng'}:
            return getattr(self, rng_type)
        raise KeyError(f'Unknown rng type {repr(rng_type)}')

    def dump_as_hash(self):
        state = [
            random.getstate(),
            self.frng.getstate(),
            self.prng.getstate(),
        ]
        self.hash = xxhash.xxh64(repr(state).encode()).hexdigest()
