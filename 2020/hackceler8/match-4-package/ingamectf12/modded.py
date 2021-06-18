#!/usr/bin/python3
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
import random
import gmpy2
import binascii

FLAG = b'HCL8{HowDidYouManageToFoolMe?!}'

p = gmpy2.next_prime(random.SystemRandom().getrandbits(512))
q = gmpy2.next_prime(random.SystemRandom().getrandbits(512))

n = p * q
e = 65537
phi = (p-1) * (q-1)
d = gmpy2.invert(e, phi)

print('''
Welcome to our RSA Secure Oracle!
We have anti-hacker protection and a bit of obscurity as you don't even have the
full public key!

TODO: check this is actually secure.

Public key: e=%d, n=<REDACTED>
''' % e)

while True:
    print('''
1) Encrypt data
2) Decrypt data
3) Get encrypted flag
''')
    choice = int(input('> '))
    if choice == 1:
        print('Please gimme the message as int:')
        msg = int(input('> '))
        print(pow(msg, e, n))
    elif choice == 2:
        print('Please gimme the message as int:')
        msg = int(input('> '))
        output = int(pow(msg, d, n))
        if b'HCL8{' in output.to_bytes(output.bit_length() // 8 + 1, byteorder='big'):
            print('Hacker detected!')
            exit(1)
        print(output)
    elif choice == 3:
        print('Here\'s your flag, not that you can do much with it:')
        print(pow(int.from_bytes(FLAG, byteorder='big'), e, n))
