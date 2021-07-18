# Copyright 2021 Google LLC
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

import random

random.seed(1337)

FLAG = "CTF{pr3pr0cess0r_pr0fe5sor}"

multipliers = []
for i in range(32):
    multipliers.append(random.randint(0,127) * 2 + 1)

xors = [random.randint(0, 256) for i in range(32)]

def fib(n):
    a, b = 0, 1
    for i in range(n):
        a, b = b, a+b
    return a

pref = 0
prefarr = []
for i, c in enumerate(FLAG):
    c = ord(c)
    c *= multipliers[i]
    c += fib(i+1)
    c ^= xors[i]
    pref += c
    pref &= 255
    prefarr.append(pref)

print("rom %s %s %s" % (
    " ".join(str(c) for c in multipliers),
    " ".join(str(c) for c in xors),
    " ".join(str(c) for c in prefarr)
    ))


