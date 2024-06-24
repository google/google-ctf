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

from collections import defaultdict
from functools import cache
import itertools
from rich.progress import track
from pwn import *

from chall import IDEA

def split_chunks(num_64):
    # changed the encryption function to return 64 bit integer
    return (num_64 >> 48)&0xffff, (num_64 >> 32)&0xffff, (num_64 >> 16)&0xffff, num_64&0xffff

class RemoteChall:
    def __init__(self, host_port=None):
        if host_port:
            self.rem = remote(*host_port)
        else:
            self.rem = process("python3 chall.py", shell=True)
        self.rem.recvuntil(b"Get balance\n")
        self.oracle_count = 0
        self.bit_flips = 0

    def enc(self, m):
        self.oracle_count += 1
        self.rem.sendline(b"1")
        self.rem.sendline(hex(m).encode())
        data = self.rem.recvuntil(b"Get balance\n")
        ct = int(re.search(b'\(hex\) text: (\d+)\n',data)[1])
        return split_chunks(ct)

    def switch_key(self, mask):
        self.bit_flips += mask.bit_count()
        self.rem.sendline(b"2")
        self.rem.sendline(hex(mask).encode())
        data = self.rem.recvuntil(b"Get balance\n")

    def get_balance(self):
        self.rem.sendline(b"4")
        data = self.rem.recvuntil(b"Get balance\n")
        return int(re.search(b'Credits Remaining: (\d+)\n',data)[1])

    def get_flag(self, guess):
        self.rem.sendline(b"3")
        self.rem.sendlineafter(b'key_guess: ', hex(guess).encode())
        return self.rem.recvall().decode().strip()


BIT_INDEXES_LIST = [
    list(range(127, 112-1, -1)),
    list(range(111,  96-1, -1)),
    list(range( 95,  80-1, -1)),
    list(range( 79,  64-1, -1)),
    list(range( 63,  48-1, -1)),
    list(range( 47,  32-1, -1)),
    list(range( 31,  16-1, -1)),
    list(range( 15,   0-1, -1)),

    list(range(102,  87-1, -1)),
    list(range( 86,  71-1, -1)),
    list(range( 70,  55-1, -1)),
    list(range( 54,  39-1, -1)),
    list(range( 38,  23-1, -1)),
    list(range( 22,   7-1, -1)),
    list(range(  6,   0-1, -1)) + list(range(127, 119-1, -1)),
    list(range(118, 103-1, -1)),

    list(range( 77,  62-1, -1)),
    list(range( 61,  46-1, -1)),
    list(range( 45,  30-1, -1)),
    list(range( 29,  14-1, -1)),
    list(range( 13,   0-1, -1)) + list(range(127, 126-1, -1)),
    list(range(125, 110-1, -1))
]

class IDEAPartialKey:
    def __init__(self):
        self.bits = [None for _ in range(128)]
    
    # return a tuple of length 16 indicating the indexes of the bits
    def __subkey_bit_indexes(self, round: int, index: int) -> list[int]:
        real_index = 6*(round-1) + (index-1)
        return BIT_INDEXES_LIST[real_index]

    def subkey(self, round: int, index: int) -> int:
        bit_indexes = self.__subkey_bit_indexes(round, index)
        # The subkey is not deterministic
        subkey_bits = [self.bits[idx] for idx in bit_indexes]
        if any([b is None for b in subkey_bits]): return None
        return sum(b<<(15-i) for i, b in enumerate(subkey_bits))
    
    # return false if there are colliding bits
    def set_subkey(self, round: int, index: int, subkey: int):
        bit_indexes = self.__subkey_bit_indexes(round, index)
        for i in range(16):
            if (self.bits[bit_indexes[15-i]] is not None and
                self.bits[bit_indexes[15-i]] != (subkey>>i) & 1):
                return False
            self.bits[bit_indexes[15-i]] = (subkey>>i) & 1
        return True

    def subkeys(self, round: int, index: int) -> list[int]:
        subkeys = []
        for subkey_bits in itertools.product(
            *[
                [self.bits[idx]] if self.bits[idx] is not None else [0, 1]
                for idx in self.__subkey_bit_indexes(round, index)
            ]
        ):
            subkeys.append(sum([b<<(15-i) for i, b in enumerate(subkey_bits)]))
        return subkeys

    @property
    def key(self):
        assert all(b in [0, 1] for b in self.bits)
        return sum(b<<i for i, b in enumerate(self.bits))

    # return false if there are colliding bits
    def set_key(self, key: int):
        for i in range(128):
            if (self.bits[i] is not None and
                self.bits[i] != (key>>i) & 1):
                return False
            self.bits[i] = (key>>i) & 1
        return True

    @property
    def keys(self):
        for key_bits in itertools.product(
            *[
                [self.bits[idx]] if self.bits[idx] is not None else [0, 1]
                for idx in range(128)
            ]
        ):
            yield sum(b<<i for i, b in enumerate(key_bits))

    def copy(self):
        pk = IDEAPartialKey()
        pk.bits = self.bits[:]
        return pk

# ===

# Util
minv = [pow(i, 65535, 65537) & 0xffff for i in range(65536)]

def mul(a, b):
    if a == 0: a = 65536
    if b == 0: b = 65536
    return (a * b % 65537) & 0xffff

# Find b such that mul(a, b) == c
def div(c, a):
    return (c * minv[a] % 65537) & 0xffff

def add(a, b):
    return (a + b) & 0xffff

def sub(a, b):
    return (a - b) & 0xffff

def xor(a, b):
    return a ^ b

# ===

# Step 0: Obtain the first set of message-ciphertext pairs that we might need
def step0(rem):
    m1 = 0x0000_0000_0000_0000
    m3 = 0x0000_0000_0000_0001
    c1 = rem.enc(m1) # Encrypt(k, (0x0000, 0x0000, 0x0000, 0x0000))
    c3 = rem.enc(m3) # Encrypt(k, (0x0000, 0x0000, 0x0000, 0x0001))

    m5_1_list = [pow(5, -i, 65537) & 0xffff for i in range(257)]
    c5_list = [rem.enc(m5_1<<48) for m5_1 in m5_1_list] # Encrypt(k, (m51, 0x0000, 0x0000, 0x0000)

    rem.switch_key(1<<111)

    m2 = 0x0000_8000_0000_0000
    m4 = 0x0000_8000_0000_0001
    c2 = rem.enc(m2) # Encrypt(k xor 2^111, (0x0000, 0x8000, 0x0000, 0x0000))
    c4 = rem.enc(m4) # Encrypt(k xor 2^111, (0x0000, 0x8000, 0x0000, 0x0001))

    rem.switch_key(1<<112 | 1<<111)
    m6_1_list = [pow(5, 257*i, 65537) & 0xffff for i in range(255)]
    c6_list = [rem.enc(m6_1<<48) for m6_1 in m6_1_list] # Encrypt(k xor 2^112, (m61, 0x0000, 0x0000, 0x0000))

    return (c1, c2, c3, c4, c5_list, c6_list)

# Step 1: Recover (k41, k43)
def step1(rem, candidate_key_list, c1, c2, c3, c4):
    new_candidate_key_list = []

    c1_1, _, c1_3, _ = c1 # Enc(k,          (0x0000, 0x0000, 0x0000, 0x0000))
    c2_1, _, c2_3, _ = c2 # Enc(k ^ 2**111, (0x0000, 0x0000, 0x0000, 0x0000))
    c3_1, _, c3_3, _ = c3 # Enc(k,          (0x0000, 0x0000, 0x0000, 0x0001))
    c4_1, _, c4_3, _ = c4 # Enc(k ^ 2**111, (0x0000, 0x0000, 0x0000, 0x0001))

    for pk in candidate_key_list:
        middletext_to_k41_map = defaultdict(list)
        for k41 in pk.subkeys(4, 1):
            s1_3_11 = div(c1_1, k41)
            s2_3_11 = div(c2_1, k41)
            s3_3_11 = div(c3_1, k41)
            s4_3_11 = div(c4_1, k41)

            middletext = (s1_3_11^s2_3_11, s3_3_11^s4_3_11)
            middletext_to_k41_map[middletext].append(k41)

        for k43 in pk.subkeys(4, 3):
            s1_3_13 = sub(c1_3, k43)
            s2_3_13 = sub(c2_3, k43)
            s3_3_13 = sub(c3_3, k43)
            s4_3_13 = sub(c4_3, k43)

            middletext = (s1_3_13^s2_3_13, s3_3_13^s4_3_13)
            for k41 in middletext_to_k41_map[middletext]:
                new_pk = pk.copy()
                if not new_pk.set_subkey(4, 1, k41): continue
                if not new_pk.set_subkey(4, 3, k43): continue
                new_candidate_key_list.append(new_pk)

    return new_candidate_key_list

# Step 2: Recover k01
def step2(rem, candidate_key_list, c5_list, c6_list):
    new_candidate_key_list = []

    m5_1_list = [pow(5, -i, 65537) & 0xffff for i in range(257)]
    m6_1_list = [pow(5, 257*i, 65537) & 0xffff for i in range(255)]
    
    # solns[x] are the solutions of k such that k / (k^1) = x.
    # this could solve k * x1 == (k^1) * x2, where x = x2/x1
    solns = [[] for _ in range(65536)]
    for k in range(65536):
        solns[div(k, k^1)].append(k)

    for pk in track(candidate_key_list):
        middletext_to_m5_1_map = defaultdict(list)
        middletext_to_m6_1_map = defaultdict(list)

        k41 = pk.subkey(4, 1)
        k43 = pk.subkey(4, 3)

        for m5_1, c5 in zip(m5_1_list, c5_list):
            c5_1, _, c5_3, _ = c5 # Enc(k, (m5_1, 0x0000, 0x0000, 0x0000))
            s5_3_11 = div(c5_1, k41)
            s5_3_13 = sub(c5_3, k43)

            middletext = s5_3_11 ^ s5_3_13
            middletext_to_m5_1_map[middletext].append(m5_1)

        for m6_1, c6 in zip(m6_1_list, c6_list):
            c6_1, _, c6_3, _ = c6 # Enc(k, (m6_1, 0x0000, 0x0000, 0x0000))
            s6_3_11 = div(c6_1, k41)
            s6_3_13 = sub(c6_3, k43)

            middletext = s6_3_11 ^ s6_3_13
            middletext_to_m6_1_map[middletext].append(m6_1)

        for middletext in range(2**16):
            for m5_1, m6_1 in itertools.product(middletext_to_m5_1_map[middletext],
                                                middletext_to_m6_1_map[middletext]):
                for k11 in solns[div(m6_1, m5_1)]:
                    new_pk = pk.copy()
                    if not new_pk.set_subkey(1, 1, k11): continue
                    new_candidate_key_list.append(new_pk)

    return new_candidate_key_list

# Step 3: Recover (k42, k44)
def step3(rem, candidate_key_list, c1, c3):
    new_candidate_key_list = []

    k11_list = set(pk.subkey(1, 1) for pk in candidate_key_list)
    rem.switch_key(1<<112 | 1<<127)

    k11_to_c7_map = defaultdict(None)
    k11_to_c8_map = defaultdict(None)
    for k11 in k11_list:
        m7_1 = div(mul(k11, 0), k11 ^ (1<<15))

        k11_to_c7_map[k11] = rem.enc(m7_1<<48)     # Enc(k, (m71, 0x0000, 0x0000, 0x0000))
        k11_to_c8_map[k11] = rem.enc(m7_1<<48 | 1) # Enc(k, (m71, 0x0000, 0x0000, 0x0001))

    for pk in candidate_key_list:
        k11 = pk.subkey(1, 1)

        k42_list = pk.subkeys(4, 2)
        k44_list = pk.subkeys(4, 4)
 
        c7, c8 = k11_to_c7_map[k11], k11_to_c8_map[k11]
        _, c1_2, _, c1_4 = c1
        _, c3_2, _, c3_4 = c3
        _, c7_2, _, c7_4 = c7
        _, c8_2, _, c8_4 = c8

        middletext_to_k42_map = defaultdict(list)

        for k42 in k42_list:
            s1_3_12 = sub(c1_2, k42)
            s3_3_12 = sub(c3_2, k42)
            s7_3_12 = sub(c7_2, k42)
            s8_3_12 = sub(c8_2, k42)

            middletext = (s1_3_12^s7_3_12, s3_3_12^s8_3_12)
            middletext_to_k42_map[middletext].append(k42)

        for k44 in k44_list:
            s1_3_14 = div(c1_4, k44)
            s3_3_14 = div(c3_4, k44)
            s7_3_14 = div(c7_4, k44)
            s8_3_14 = div(c8_4, k44) 

            middletext = (s1_3_14^s7_3_14, s3_3_14^s8_3_14)
            for k42 in middletext_to_k42_map[middletext]:
                new_pk = pk.copy()
                if not new_pk.set_subkey(4, 2, k42): continue
                if not new_pk.set_subkey(4, 4, k44): continue
                new_candidate_key_list.append(new_pk)

    return new_candidate_key_list

# Return a list of (x, y)'s such that (x + y) ^ [x + (y ^ a)] = b
@cache
def step4_subsolve(a, b):
    solns = []
    # Here we use the substitution u = (x + y) ^ b, and
    # perform MITM with (b ^ u) - u = y - (y ^ a).
    lhs = defaultdict(list)
    for u in range(2**16):
        lhs[sub(xor(b, u), u)].append(u)

    rhs = defaultdict(list)
    for y in range(2**16):
        rhs[sub(y, xor(y, a))].append(y)

    for v in range(2**16):
        for u, y in itertools.product(lhs[v], rhs[v]):
            x = sub(xor(b, u), y)
            solns.append((x, y))
    return solns


# Step 4: Recover (k35, k36)
def step4(rem, candidate_key_list, c1, c2, c3, c4):
    new_candidate_key_list = []

    c1_1, c1_2, c1_3, c1_4 = c1
    c2_1, c2_2, _,    c2_4 = c2
    c3_1, c3_2, c3_3, c3_4 = c3
    c4_1, c4_2, _,    c4_4 = c4

    for pk in track(candidate_key_list):
        k41 = pk.subkey(4, 1)
        k42 = pk.subkey(4, 2)
        k43 = pk.subkey(4, 3)
        k44 = pk.subkey(4, 4)

        s1_3_11 = div(c1_1, k41)
        s2_3_11 = div(c2_1, k41)
        s3_3_11 = div(c3_1, k41)
        s4_3_11 = div(c4_1, k41)

        s1_3_12 = sub(c1_2, k42)
        s2_3_12 = sub(c2_2, k42)
        s3_3_12 = sub(c3_2, k42)
        s4_3_12 = sub(c4_2, k42)

        s1_3_13 = sub(c1_3, k43)
        s3_3_13 = sub(c3_3, k43)

        s1_3_14 = div(c1_4, k44)
        s2_3_14 = div(c2_4, k44 ^ (1<<1))
        s3_3_14 = div(c3_4, k44)
        s4_3_14 = div(c4_4, k44 ^ (1<<1))

        s1_3_5 = xor(s1_3_11, s1_3_13)
        s3_3_5 = xor(s3_3_11, s3_3_13)

        s1_3_6 = xor(s1_3_12, s1_3_14)
        s2_3_6 = xor(s2_3_12, s2_3_14)
        s3_3_6 = xor(s3_3_12, s3_3_14)
        s4_3_6 = xor(s4_3_12, s4_3_14)

        k35_and_k36_list = []

        s1_3_7_and_s1_3_10_list = step4_subsolve(s1_3_11^s2_3_11, s1_3_12^s2_3_12)
        for s1_3_7, s1_3_10 in s1_3_7_and_s1_3_10_list:
            s1_3_8 = add(s1_3_6, s1_3_7)

            k35 = div(s1_3_7, s1_3_5)
            k36 = div(s1_3_10, s1_3_8)
            k35_and_k36_list.append((k35, k36))

        for k35, k36 in k35_and_k36_list:
            # Check against the first pair
            s1_3_7 = mul(s1_3_5, k35)
            s2_3_7 = s1_3_7

            s1_3_8 = add(s1_3_6, s1_3_7)
            s2_3_8 = add(s2_3_6, s2_3_7)
 
            s1_3_10 = mul(s1_3_8, k36)
            s2_3_10 = mul(s2_3_8, k36)

            s1_3_1 = xor(s1_3_10, s1_3_11)
            s2_3_1 = xor(s2_3_10, s2_3_11)

            if s1_3_1 != s2_3_1: continue

            # Check against the second pair
            s3_3_7 = mul(s3_3_5, k35)
            s4_3_7 = s3_3_7

            s3_3_8 = add(s3_3_6, s3_3_7)
            s4_3_8 = add(s4_3_6, s4_3_7)

            s3_3_10 = mul(s3_3_8, k36)
            s4_3_10 = mul(s4_3_8, k36)

            s3_3_1 = xor(s3_3_10, s3_3_11)
            s4_3_1 = xor(s4_3_10, s4_3_11)

            if s3_3_1 != s4_3_1: continue

            new_pk = pk.copy()
            if not new_pk.set_subkey(3, 5, k35): continue
            if not new_pk.set_subkey(3, 6, k36): continue
            new_candidate_key_list.append(new_pk)

    return new_candidate_key_list

# Step 5: Recover k34
def step5(rem, candidate_key_list, c1, c2):
    new_candidate_key_list = []

    c1_1, c1_2, c1_3, c1_4 = c1
    _,    c2_2, _,    c2_4 = c2

    for pk in candidate_key_list:
        k35 = pk.subkey(3, 5)
        k36 = pk.subkey(3, 6)
        k41 = pk.subkey(4, 1)
        k42 = pk.subkey(4, 2)
        k43 = pk.subkey(4, 3)
        k44 = pk.subkey(4, 4)

        s1_3_11 = div(c1_1, k41)

        s1_3_12 = sub(c1_2, k42)
        s2_3_12 = sub(c2_2, k42)

        s1_3_13 = sub(c1_3, k43)

        s1_3_14 = div(c1_4, k44)
        s2_3_14 = div(c2_4, k44 ^ (1<<1))

        s1_3_5 = xor(s1_3_11, s1_3_13)
        s2_3_5 = s1_3_5

        s1_3_6 = xor(s1_3_12, s1_3_14)
        s2_3_6 = xor(s2_3_12, s2_3_14)

        s1_3_7 = mul(s1_3_5, k35)

        for k34 in pk.subkeys(3, 4):
            s1_3_7 = mul(s1_3_5, k35)
            s2_3_7 = mul(s2_3_5, k35)

            s1_3_8 = add(s1_3_6, s1_3_7)
            s2_3_8 = add(s2_3_6, s2_3_7)

            s1_3_10 = mul(s1_3_8, k36)
            s2_3_10 = mul(s2_3_8, k36)

            s1_3_9 = add(s1_3_7, s1_3_10)
            s2_3_9 = add(s2_3_7, s2_3_10)

            s1_3_4 = xor(s1_3_9, s1_3_14)
            s2_3_4 = xor(s2_3_9, s2_3_14)

            s1_2_14 = div(s1_3_4, k34)
            s2_2_14 = div(s2_3_4, k34 ^ (1<<8))

            if s1_2_14 != s2_2_14: continue

            new_pk = pk.copy()
            new_pk.set_subkey(3, 4, k34)
            new_candidate_key_list.append(new_pk)

    return new_candidate_key_list

# Step 6: Recover k13
def step6(rem, candidate_key_list, c1):
    new_candidate_key_list = []

    m1_1, _,    m1_3, _    = 0x0000, 0x0000, 0x0000, 0x0000
    c1_1, c1_2, c1_3, c1_4 = c1

    for pk in candidate_key_list:
        k11 = pk.subkey(1, 1)
        k21 = pk.subkey(2, 1)
        k22 = pk.subkey(2, 2)
        k25 = pk.subkey(2, 5)
        k26 = pk.subkey(2, 6)
        k31 = pk.subkey(3, 1)
        k32 = pk.subkey(3, 2)
        k33 = pk.subkey(3, 3)
        k34 = pk.subkey(3, 4)
        k35 = pk.subkey(3, 5)
        k36 = pk.subkey(3, 6)
        k41 = pk.subkey(4, 1)
        k42 = pk.subkey(4, 2)
        k43 = pk.subkey(4, 3)
        k44 = pk.subkey(4, 4)

        s1_3_11 = div(c1_1, k41)
        s1_3_12 = sub(c1_2, k42)
        s1_3_13 = sub(c1_3, k43)
        s1_3_14 = div(c1_4, k44)
        s1_3_5 = xor(s1_3_11, s1_3_13)
        s1_3_6 = xor(s1_3_12, s1_3_14)
        s1_3_7 = mul(s1_3_5, k35)
        s1_3_8 = add(s1_3_6, s1_3_7)
        s1_3_10 = mul(s1_3_8, k36)
        s1_3_9 = add(s1_3_7, s1_3_10)
        s1_3_1 = xor(s1_3_10, s1_3_11)
        s1_3_2 = xor(s1_3_9, s1_3_12)
        s1_3_3 = xor(s1_3_10, s1_3_13)
        s1_3_4 = xor(s1_3_9, s1_3_14)
        s1_2_11 = div(s1_3_1, k31)
        s1_2_13 = sub(s1_3_2, k32)
        s1_2_12 = sub(s1_3_3, k33)
        s1_2_14 = div(s1_3_4, k34)
        s1_2_5 = xor(s1_2_11, s1_2_13)
        s1_2_6 = xor(s1_2_12, s1_2_14)
        s1_2_7 = mul(s1_2_5, k25)
        s1_2_8 = add(s1_2_6, s1_2_7)
        s1_2_10 = mul(s1_2_8, k26)
        s1_2_9 = add(s1_2_7, s1_2_10)
        s1_2_1 = xor(s1_2_10, s1_2_11)
        s1_2_2 = xor(s1_2_9, s1_2_12)
        s1_1_1 = mul(m1_1, k11)
        s1_1_11 = div(s1_2_1, k21)
        s1_1_10 = xor(s1_1_11, s1_1_1)
        s1_1_13 = sub(s1_2_2, k22)
        s1_1_3 = xor(s1_1_10, s1_1_13)

        k13 = sub(s1_1_3, m1_3)

        new_pk = pk.copy()
        new_pk.set_subkey(1, 3, k13)
        new_candidate_key_list.append(new_pk)

    return new_candidate_key_list

# Recover the full key
def step7(rem, candidate_key_list, c1, c3):
    new_candidate_key_list = []

    m1 = 0x0000_0000_0000_0000
    m3 = 0x0000_0000_0000_0001

    for pk in candidate_key_list:
        for key in pk.keys:
            cipher = IDEA(key, rounds=3)
            if split_chunks(cipher.encrypt(m1)) != c1: continue
            if split_chunks(cipher.encrypt(m3)) != c3: continue

            new_pk = pk.copy()
            if not new_pk.set_key(key): continue
            new_candidate_key_list.append(new_pk)

    return new_candidate_key_list

# ===

def attempt():
    rem = RemoteChall()

    c1, c2, c3, c4, c5_list, c6_list = step0(rem)
    print(f'Step 0 done |   0/128 bits recovered | {rem.oracle_count} calls invoked and {rem.bit_flips} bits flipped')

    candidate_key_list = [IDEAPartialKey()]
    for i, (step_fn, c_list) in enumerate([
        (step1, [c1, c2, c3, c4]),
        (step2, [c5_list, c6_list]),
        (step3, [c1, c3]),
        (step4, [c1, c2, c3, c4]),
        (step5, [c1, c2]),
        (step6, [c1]),
        (step7, [c1, c3]),
    ], start=1):
        candidate_key_list = step_fn(rem, candidate_key_list, *c_list)
        bits_recovered = (sum(b is not None for b in candidate_key_list[0].bits)
                          if len(candidate_key_list) else 0) # bugged!
        print(f'Step {i} done | {bits_recovered:3d}/128 bits recovered | {rem.oracle_count} calls invoked and {rem.bit_flips} bits flipped | {len(candidate_key_list)} candidates obtained')

        if len(candidate_key_list) > 16:
            print(f"Too many candidates. Let's skip this attempt...")
            rem.rem.close()
            return False

    assert len(candidate_key_list) == 1
    pk, = candidate_key_list
    key = pk.key
    print(f'Key recovered: {hex(key)}')
    
    flag = rem.get_flag(key)
    print(f'{flag = }')
    return True


def main():
    while not attempt(): continue

if __name__ == '__main__':
    main()
