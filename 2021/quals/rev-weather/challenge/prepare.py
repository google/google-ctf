# Copyright 2021 Google LLC
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
random.seed(133788)

city = "TheNewFlagHillsByTheCtfWoods"
flag = "CTF{curs3d_r3curs1ve_pr1ntf}"
print(len(city))
print(len(flag))


def isprime(n):
    for i in range(2, n):
        if n%i == 0:
            return False
    return True

def collatz(n):
    if n == 1: return 0
    if n % 2 == 0:
        return 1 + collatz(n//2)
    return 1 + collatz(3*n+1)

primes = [n for n in range(13200, 13600) if isprime(n)]
xors = [random.randint(0,2**32-1) for i in range(len(flag)//4)]

arr = [ord(c) for c in city]
cit = [ord(c) for c in city]
flg = [ord(c) for c in flag]
print(arr)
for i, a in enumerate(arr):
    arr[i] = (((a ^ primes[i]) & 255) + collatz(i+1)) & 255
print(arr)
print("Check code:")
print("mov r0, 0") # XorResult
for i in range(len(city)//4):
    print("mov r1, %d" % (i*4))
    print("add r1, city2")
    print("mov r1, [r1]")
    x = arr[i*4] + arr[i*4+1]*256 + arr[i*4+2]*256**2 + arr[i*4+3]*256**3
    print("mov r2, 0")
    while x:
        if x >= 2*10**9:
            y = random.randint(1, 2*10**9)
            print("add r2, %d" % y)
            x -= y
        else:
            print("add r2, %d" % x)
            x -= x
    print("xor r1, r2")
    print("or r0, r1")
print("call0 goodcity, r0")
print("---")

print("Decrypt code:")
print("mov r0, 123456789")
sofar = 123456789
for i in range(len(city)//4):
    print("mov r1, %d" % (i*4))
    print("add r1, city")
    print("mov r1, [r1]")
    print("xor r0, r1")
    x = cit[i*4] + cit[i*4+1]*256 + cit[i*4+2]*256**2 + cit[i*4+3]*256**3
    sofar ^= x
    z = flg[i*4] + flg[i*4+1]*256 + flg[i*4+2]*256**2 + flg[i*4+3]*256**3
    z ^= sofar
    print("mov r2, 0")
    while z:
        if z >= 2*10**9:
            y = random.randint(1, 2*10**9)
            print("add r2, %d" % y)
            z -= y
        else:
            print("add r2, %d" % z)
            z -= z
    print("xor r2, r0")
    print("mov r1, %d" % (i*4))
    print("add r1, flag")
    print("mov [r1], r2")

