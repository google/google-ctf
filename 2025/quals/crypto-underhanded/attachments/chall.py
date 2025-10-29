#!/usr/bin/python3

# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import signal
import os
from aes import AES

def tle_handler(*args):
    print('⏰')
    sys.exit(0)

def challenge():
    k = os.urandom(16)
    aes = AES(k)

    # I will encrypt FIVE messages for you, that's it.
    for _ in range(5):
        m = bytes.fromhex(input('📄 '))
        c = aes.encrypt(m)
        print('🤫', c.hex())

    _k = bytes.fromhex(input('🔑 '))
    if k != _k: raise Exception('incorrect guess!')

# We validated that our AES has the same output as what cryptodome
# provided. You can break this only if AES is intrinsically broken.
def main():
    signal.signal(signal.SIGALRM, tle_handler)
    signal.alarm(300)

    with open('/flag.txt', 'r') as f:
      flag = f.read()

    try:
        # Once is happenstance. Twice is coincidence...
        # Sixteen times is a recovery of the pseudorandom number generator.
        for _ in range(16):
            challenge()
            print('💡')
        print(f'🏁 {flag}')
    except:
        print('👋')

if __name__ == '__main__':
    main()
