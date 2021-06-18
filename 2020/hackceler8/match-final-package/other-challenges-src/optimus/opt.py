# Copyright 2020 Google LLC
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

flag = b"HCL8{why_0pt1miz3_1f_i7_w0rk5?}"
n = 31337
mod = 0x31337

arr = [0]
for i in range(1, n):
    arr.append(arr[-1] + pow(i,i,mod))

res = "".join(str(x) for x in arr[-3:])
print(arr, res)


key = hashlib.sha256(res.encode()).digest()

res = []
for k, f in zip(key, flag):
    res.append(k^f)

print("flag =", bytes(res))
print("n =", n)
