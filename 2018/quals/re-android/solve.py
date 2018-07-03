# Copyright 2018 Google LLC
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

# Tool to verify the solution

from Crypto.Cipher import AES
from hashlib import sha256

flag = [
	-61, 15, 25, -115, -46, -11, 65, -3, 34, 93, -39, 98, 123, 17, 42, -121, 60,
	40, -60, -112, 77, 111, 34, 14, -31, -4, -7, 66, 116, 108, 114, -122
]
flag = ''.join([chr(x & 0xFF) for x in flag])


seed = [211, 52, 228, 33, 61, 253, 49, 167, 48, 53, 117, 165, 170, 56, 212, 158,
	21, 110, 4, 22, 86, 26, 36, 90, 155, 52, 212, 16, 198, 245, 70, 143]

rounds = 1000000

def _Round(seed):
	arr = ''.join(map(chr, seed))
	d = sha256(arr).digest()
	return map(ord, d)

count = 0
for i in xrange(rounds):
	if count % 10000 == 0:
		print count
	seed = _Round(seed)
	count += 1

key = ''.join(map(chr, seed))
aes = AES.new(key, AES.MODE_ECB)
print aes.decrypt(flag)
