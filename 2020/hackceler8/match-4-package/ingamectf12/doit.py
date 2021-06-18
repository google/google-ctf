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
import gmpy2

e = 65537

enc2 = int(input('Gimme the encryption of 2: '))
enc3 = int(input('Gimme the encryption of 3: '))
enc5 = int(input('Gimme the encryption of 5: '))
enc7 = int(input('Gimme the encryption of 7: '))

n = gmpy2.gcd(gmpy2.gcd(gmpy2.gcd(enc2 - 2**e, enc3 - 3**e), enc5 - 5**e), enc7 - 7**e)

print('Get the encrypted flag and get the decryption of -$encrypted_flag')
almost_flag = int(input('Gimme the decryption of -$encrypted_flag: '))

flag = hex(-almost_flag % n)[2:]
print(flag)

