# Copyright 2023 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     https://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import subprocess
from math import gcd
from functools import reduce
from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes, isPrime

class _LCG:
    def __init__(self, multiplier, increment, modulus, lcg_s):
        self.state = lcg_s
        self.lcg_m = multiplier
        self.lcg_c = increment
        self.lcg_n = modulus

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

def crack_unknown_increment(states, modulus, multiplier):
    increment = (states[1] - states[0]*multiplier) % modulus
    return modulus, multiplier, increment

def crack_unknown_multiplier(states, modulus):
    multiplier = (states[2] - states[1]) * pow(states[1] - states[0], -1, modulus) % modulus
    return crack_unknown_increment(states, modulus, multiplier)

def crack_unknown_modulus(states):
    diffs = [s1 - s0 for s0, s1 in zip(states, states[1:])]
    zeroes = [t2*t0 - t1*t1 for t0, t1, t2 in zip(diffs, diffs[1:], diffs[2:])]
    modulus = abs(reduce(gcd, zeroes))
    return crack_unknown_multiplier(states, modulus)

if __name__ == '__main__':

    # Get 'n' and 'e'
    f = open("public.pem", "r")
    key = RSA.importKey(f.read())
    _n = key.n
    _e = key.e

    # Factor out 'n'
    # Mathematical Approach 1
    _dump_vals = []
    with open("dump.txt", "r") as _dump:
        for _val in _dump:
            _dump_vals.append(int(_val))

    modulus, multiplier, increment = crack_unknown_modulus(_dump_vals)
    print(f"Extracted modulus: {modulus}, multiplier: {multiplier}, increment: {increment}")

    seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
    _lcg = _LCG(multiplier, increment, modulus, seed)
    _primes_arr = []
    
    for i in range(8):
        while True:
            _prime_candidate = _lcg.next()
            if not isPrime(_prime_candidate):
                continue
            elif _prime_candidate.bit_length() != 512:
                continue
            else:
                _primes_arr.append(_prime_candidate)
                break

    # Calculate totient
    _phi = 1
    for k in _primes_arr:
        _phi *= (k - 1)
    
    # Get privte key
    _d = pow(_e, -1, _phi)

    # Decrypt
    flag = open("flag.txt", "rb")

    # Concat bytes in case '\n' bytes are present
    flag_bytes = b''
    for b in flag:
        flag_bytes += b

    _flag = int.from_bytes(flag_bytes, 'little')
    
    _dec = pow(_flag, _d, _n)
    print("[*] FLAG:\t", long_to_bytes(_dec).decode())

    # Utility Approach
    """ Commented out for now
    raw_factors = subprocess.run([".\yafu-x64.exe", f"factor({key.n})"], capture_output=True)
    val_list = raw_factors.stdout.split(b'found***')[1].split(b'\r\n\r\n')[1].split(b'\r\n')
    primes_arr_ = []
    for val in val_list:
        primes_arr_.append(int(val.split(b'=')[1]))

    # Calculate totient
    totient_ = 1
    for k in primes_arr_:
        totient_ *= (k - 1)
    
    # Get privte key
    d = pow(key.e, -1, totient_)
    _dec = pow(_enc, d, n)
    print("FLAG:\t", long_to_bytes(_dec))
    """
