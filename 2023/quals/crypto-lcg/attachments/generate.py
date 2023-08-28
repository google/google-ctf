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

from secret import config
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, isPrime

class LCG:
    lcg_m = config.m
    lcg_c = config.c
    lcg_n = config.n

    def __init__(self, lcg_s):
        self.state = lcg_s

    def next(self):
        self.state = (self.state * self.lcg_m + self.lcg_c) % self.lcg_n
        return self.state

if __name__ == '__main__':

    assert 4096 % config.it == 0
    assert config.it == 8
    assert 4096 % config.bits == 0
    assert config.bits == 512

    # Find prime value of specified bits a specified amount of times
    seed = 211286818345627549183608678726370412218029639873054513839005340650674982169404937862395980568550063504804783328450267566224937880641772833325018028629959635
    lcg = LCG(seed)
    primes_arr = []
    
    dump = True
    items = 0
    dump_file = open("dump.txt", "w")

    primes_n = 1
    while True:
        for i in range(config.it):
            while True:
                prime_candidate = lcg.next()
                if dump:
                    dump_file.write(str(prime_candidate) + '\n')
                    items += 1
                    if items == 6:
                        dump = False
                        dump_file.close()
                if not isPrime(prime_candidate):
                    continue
                elif prime_candidate.bit_length() != config.bits:
                    continue
                else:
                    primes_n *= prime_candidate
                    primes_arr.append(prime_candidate)
                    break
        
        # Check bit length
        if primes_n.bit_length() > 4096:
            print("bit length", primes_n.bit_length())
            primes_arr.clear()
            primes_n = 1
            continue
        else:
            break

    # Create public key 'n'
    n = 1
    for j in primes_arr:
        n *= j
    print("[+] Public Key: ", n)
    print("[+] size: ", n.bit_length(), "bits")

    # Calculate totient 'Phi(n)'
    phi = 1
    for k in primes_arr:
        phi *= (k - 1)

    # Calculate private key 'd'
    d = pow(config.e, -1, phi)

    # Generate Flag
    assert config.flag.startswith(b"CTF{")
    assert config.flag.endswith(b"}")
    enc_flag = bytes_to_long(config.flag)
    assert enc_flag < n

    # Encrypt Flag
    _enc = pow(enc_flag, config.e, n)

    with open ("flag.txt", "wb") as flag_file:
        flag_file.write(_enc.to_bytes(n.bit_length(), "little"))

    # Export RSA Key
    rsa = RSA.construct((n, config.e))
    with open ("public.pem", "w") as pub_file:
        pub_file.write(rsa.exportKey().decode())