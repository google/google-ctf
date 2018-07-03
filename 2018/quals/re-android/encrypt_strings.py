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

def encode(s):
	buf = [ord(s[0])]
	for c1, c2 in zip(s, s[1:]):
		buf.append(ord(c2) - ord(c1) & 0xFF)

	buf.append(-ord(s[-1]) & 0xFF)
	return buf

strings = [
  "javax/crypto/Cipher",
  "javax/crypto/spec/SecretKeySpec",
  "java/security/MessageDigest",
  "java/util/Random",
  "getInstance",
  "<init>",
  "init",
  "doFinal",
  "getInstance",
  "update",
  "digest",
  "<init>",
  "nextBytes",
  "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
  "([BLjava/lang/String;)V",
  "(ILjava/security/Key;)V",
  "([B)[B",
  "(Ljava/lang/String;)Ljava/security/MessageDigest;",
  "([B)V",
  "()[B",
  "(J)V",
  "([B)V",
  "AES/ECB/NoPadding",
  "AES",
  "SHA-256",
]

fmt = 'uint8_t kEnc[] = {%s};'
for s in strings:
	payload = encode(s)
	print fmt % (', '.join(map(str, payload)))
