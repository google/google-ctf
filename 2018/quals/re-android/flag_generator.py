# Copyright 2018 Google LLC
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Tool to generate the payload for the flag

from Crypto.Cipher import AES
from hashlib import sha256

# http://thecodelesscode.com/case/195
# A fitting quote for a RE challenge, I think.
flag = 'CTF{ThLssOfInncncIsThPrcOfAppls}'

seed = [211, 52, 228, 33, 61, 253, 49, 167, 48, 53, 117, 165, 170, 56, 212, 158,
	21, 110, 4, 22, 86, 26, 36, 90, 155, 52, 212, 16, 198, 245, 70, 143]

# rounds = 3
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
cipher = map(ord, aes.encrypt(flag))
data = []
for b in cipher:
	if b > 0x7F:
		data.append(-0x100 + b)
	else:
		data.append(b)

print data
