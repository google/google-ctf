# Copyright 2021 Google LLC
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

import random
import string
import base64
import itertools
import time
import pickle
import os

from Crypto.Cipher import AES
from bitstring import BitArray, Bits
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from pwn import *


# This uses the multi-collision implementation by Julia Len https://github.com/julialen/key_multicollision

ALL_ZEROS = b'\x00'*16
GCM_BITS_PER_BLOCK = 128

def pad(a):
    if len(a) < GCM_BITS_PER_BLOCK:
        diff = GCM_BITS_PER_BLOCK - len(a)
        zeros = ['0'] * diff
        a = a + zeros
    return a

def bytes_to_element(val, field, a):
    bits = BitArray(val)
    result = field.fetch_int(0)
    for i in range(len(bits)):
        if bits[i]:
            result += a^i
    return result

def multi_collide_gcm(keyset, nonce, tag, first_block=None, use_magma=True):
    # initialize matrix and vector spaces
    P.<x> = PolynomialRing(GF(2))
    p = x^128 + x^7 + x^2 + x + 1
    GFghash.<a> = GF(2^128,'x',modulus=p)
    if use_magma:
        t = "p:=IrreducibleLowTermGF2Polynomial(128); GFghash<a> := ext<GF(2) | p>;"
        magma.eval(t)
    else:
        R = PolynomialRing(GFghash, 'x')

    # encode length as lens
    if first_block is not None:
        ctbitlen = (len(keyset) + 1) * GCM_BITS_PER_BLOCK
    else:
        ctbitlen = len(keyset) * GCM_BITS_PER_BLOCK
    adbitlen = 0
    lens = (adbitlen << 64) | ctbitlen
    lens_byte = int(lens).to_bytes(16,byteorder='big')
    lens_bf = bytes_to_element(lens_byte, GFghash, a)

    # increment nonce
    nonce_plus = int((int.from_bytes(nonce,'big') << 32) | 1).to_bytes(16,'big')

    # encode fixed ciphertext block and tag
    if first_block is not None:
        block_bf = bytes_to_element(first_block, GFghash, a)
    tag_bf = bytes_to_element(tag, GFghash, a)
    keyset_len = len(keyset)

    if use_magma:
        I = []
        V = []
    else:
        pairs = []

    for k in keyset:
        # compute H
        aes = AES.new(k, AES.MODE_ECB)
        H = aes.encrypt(ALL_ZEROS)
        h_bf = bytes_to_element(H, GFghash, a)

        # compute P
        P = aes.encrypt(nonce_plus)
        p_bf = bytes_to_element(P, GFghash, a)

        if first_block is not None:
            # assign (lens * H) + P + T + (C1 * H^{k+2}) to b
            b = (lens_bf * h_bf) + p_bf + tag_bf + (block_bf * h_bf^(keyset_len+2))
        else:
            # assign (lens * H) + P + T to b
            b = (lens_bf * h_bf) + p_bf + tag_bf

        # get pair (H, b*(H^-2))
        y =  b * h_bf^-2
        if use_magma:
            I.append(h_bf)
            V.append(y)
        else:
            pairs.append((h_bf, y))

    # compute Lagrange interpolation
    if use_magma:
        f = magma("Interpolation(%s,%s)" % (I,V)).sage()
    else:
        f = R.lagrange_polynomial(pairs)
    coeffs = f.list()
    coeffs.reverse()

    # get ciphertext
    if first_block is not None:
        ct = list(map(str, block_bf.polynomial().list()))
        ct_pad = pad(ct)
        ct = Bits(bin=''.join(ct_pad))
    else:
        ct = ''

    for i in range(len(coeffs)):
        ct_i = list(map(str, coeffs[i].polynomial().list()))
        ct_pad = pad(ct_i)
        ct_i = Bits(bin=''.join(ct_pad))
        ct += ct_i
    ct = ct.bytes

    return ct+tag


def get_random_password(length):
    pw_characters = string.ascii_lowercase
    return bytes(''.join(random.choice(pw_characters) for i in range(length)), 'UTF-8')


def search_for_key(keyset):
    p.sendline("3") # Decrypt oracle
    res = p.recvuntil(">>> ")

    p.sendline(create_query(keyset))
    answer = p.recvuntil(">>> ").decode('UTF-8')

    if "successful" in answer:
        if len(keyset) == 1:
            return keyset[0] # Found the correct key

        low = search_for_key(keyset[:len(keyset)//2])
        if low:
            return low
        high = search_for_key(keyset[len(keyset)//2:])
        if high:
            return high

    return None

def create_query(keyset):
    first_block = b'\x01'
    nonce = b'\x00'*12
    tag = b'\x01'*16
    ct = multi_collide_gcm(keyset, nonce, tag, first_block=first_block, use_magma=False)

    b64_nonce = base64.b64encode(nonce).decode()
    b64_ciphertext = base64.b64encode(ct).decode()
    return b64_nonce + "," + b64_ciphertext

def break_key(key_idx, queries, all_keys, all_passwords):
    """
    Returns the correct password for the key with the given index
    """
    # Set the key
    p.sendline("1")
    res = p.recvuntil(">>> ")
    p.sendline(str(key_idx))
    res = p.recvuntil(">>> ")

    for i in range(len(queries)):
        p.sendline("3") # Decrypt oracle
        res = p.recvuntil(">>> ")
        p.sendline(queries[i])

        answer = p.recvuntil(">>> ").decode('UTF-8')
        if "successful" in answer:
            # We found the correct query, now do binary search on the smaller keysets
            keyset_size = len(all_keys) // len(queries)
            keyset = all_keys[i*keyset_size:(i+1)*keyset_size]
            low = search_for_key(keyset[:len(keyset)//2])
            if low:
                return all_passwords[all_keys.index(low)]

            high = search_for_key(keyset[len(keyset)//2:])
            if high:
                return all_passwords[all_keys.index(high)]

t0 = time.time()

if os.path.isfile('all_passwords') and os.path.isfile('all_keys') and os.path.isfile('queries'):
    with open("all_passwords", "rb") as f:
        all_passwords = pickle.load(f)
    with open("all_keys", "rb") as f:
        all_keys = pickle.load(f)
    with open("queries", "rb") as f:
        queries = pickle.load(f)
else:
    # Create all possible passwords
    all_passwords = [bytes("".join(password), 'UTF-8') for password in itertools.product(string.ascii_lowercase, repeat=3)]
    all_keys = []
    for password in all_passwords:
        kdf = Scrypt(salt=b'', length=16, n=2**4, r=8, p=1)
        all_keys.append(kdf.derive(password))
    
    print("Deriving keys from password done: ", time.time() - t0)
    
    queries = []
    
    # Split initial search into 20 queries
    password_in_single_query = 26**3 // 20
    
    for query in range(20):
        queries.append(create_query(all_keys[query*password_in_single_query:(query+1)*password_in_single_query]))
        print("Query created: ", query)
    
    with open("all_passwords", "wb") as f:
        pickle.dump(all_passwords, f)
    with open("all_keys", "wb") as f:
        pickle.dump(all_keys, f)
    with open("queries", "wb") as f:
        pickle.dump(queries, f)

    print("Preparing queries done: ", time.time() - t0)

p = remote("pythia.2021.ctfcompetition.com", 1337)
res = p.recvuntil(">>> ")

# Break each key
password = break_key(0, queries, all_keys, all_passwords)
print("Got first password: ", time.time() - t0)
password += break_key(1, queries, all_keys, all_passwords)
print("Got second password: ", time.time() - t0)
password += break_key(2, queries, all_keys, all_passwords)
print("Got third password: ", time.time() - t0)

p.sendline("2")
res = p.recvuntil(">>> ")
p.sendline(password)
res = p.recvuntil(">>> ")
print(res)
