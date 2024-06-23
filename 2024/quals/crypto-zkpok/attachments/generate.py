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

import re
from Crypto.Util.number import getPrime as get_prime

def main():
    p, q = [get_prime(1024) for _ in range(2)]

    with open('message.txt', 'rb') as f:
        message = f.read()
    
    m = int.from_bytes(message, 'big')


    # Encrypts the flag using the Rabin cryptosystem
    n = p * q
    c = pow(m, 2, n)

    # Sanity check: I should not...
    assert re.search(rb'CTF{.*}', message) # ...forget the flag :)
    assert m**2 >= n # ...make m so small that someone could retrieve m by computing sqrt(c).

    with open('param.py', 'w') as f:
        f.write(f'{n = }\n')
        f.write(f'{c = }\n')
    
if __name__ == '__main__':
    main()