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

n = 31337
m = 0x31337

key = ""
p = 0
i = 0
while n:
    n -= 1
    i += 1
    print(i, p)
    a = (i ** i) % m

    if n < 3:
        key += str(p)

    p += a

key = hashlib.sha256(key.encode()).digest()
flag = b"'\x1b\xd9\x04\x9f\xe9\xb7f \x93\xda\xe1\xa3\xe7\x14\\?\xb4;Y4\xf3j\xbbp&\xdf\xfbF\\\xa6"


print(bytes(k^f for k, f in zip(key, flag)).decode())
