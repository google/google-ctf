#!/usr/bin/env python3

# Copyright 2024 Google LLC
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

from Crypto.Cipher import ARC4

key = bytes.fromhex('fcedd5ab42f188b49760fca0f99affc9')
plaintext = 'Flag: ctf{I_pr0mize_its_jUsT_mAtriCeS}\0'

rc4 = ARC4.new(key)
ciphertext = rc4.encrypt(plaintext.encode())

ciphertext_format = ', '.join(f'{x:#04x}' for x in ciphertext)
print(len(ciphertext), ciphertext_format)
