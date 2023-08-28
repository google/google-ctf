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

import numpy as np
import random

random.seed(13379001)

FLAG = "CTF{JPEG_XL_1s_tur1ng_c0mplet3!}"
FLAG = FLAG[4:-1]

factors = []

for i in range(len(FLAG)):
    factors.append([])
    for j in range(len(FLAG)):
        factors[-1].append(random.randint(0, 15))

expected = []
for i in range(len(FLAG)):
    s = 0
    for j in range(len(FLAG)):
        s += factors[i][j] * ord(FLAG[j])
    expected.append(s)

n = np.linalg.solve(factors, expected)
print("".join(chr(int(round(c))) for c in n))

for i in range(len(FLAG)):
    factors[i] = [0, 0, 0, 0] + factors[i] + [0]

print(factors)
print(expected)
