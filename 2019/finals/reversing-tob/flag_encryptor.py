#!/usr/bin/env python2
# -------------------------------------------------------------------------------------------------
# Copyright 2019 Google LLC
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
# -------------------------------------------------------------------------------------------------
# Google CTF 2019 Finals - The Onion Binary (RE)
# --------------------------------------------------------------------------------------------------
import struct
import sys
import argparse
import datetime
import textwrap
import shlex
import re
import random


key = [
    0x21, 0x85, 0xed, 0x09, 0xc9, 0xc8, 0x3f, 0xdd,
    0x91, 0xb0, 0xb0, 0x55, 0x1a, 0x2a, 0x37, 0x65,
    0x7a, 0xcf, 0xe0, 0x43, 0xaa, 0xf5, 0x01, 0x23,
    0xe7, 0x2b, 0x90, 0xa7, 0xf3, 0x3b, 0xdb, 0x77
]

# --------------------------------------------------------------------------------------------------
# Encryption algorithm.
#
def encrypt(flag):
    # Do the base checks
    if not (flag.startswith('CTF{') and flag.endswith('}')):
        print '[+] Wrong flag format!'
        return None

    flag = flag[4:-1]

    if len(key) != len(flag):
        print '[+] Flag/key mismatch!'
        return None

    # Step 1: XOR
    interm = [0]*len(key)
    for i in range(len(flag)):
        interm[i] = ord(flag[i]) ^ key[i]

    print '[+] Intermediate:', [hex(x) for x in interm]

    cipher = []

    # Step 2: Encrypt characters modulo 0
    for i in range(0, len(flag), 4):
        cipher.append((interm[i]**3 * 0xbeef) % 257)

    # Step 3: Encrypt characters modulo 1
    for i in range(1, len(flag), 4):
        cipher.append((interm[i] * 0x3541 + 0x3c97b) % 257)

    # Step 4: Encrypt characters modulo 2
    for i in range(2, len(flag), 4):
        cipher.append((interm[i] + 0xa9) % 256)

    # Step 5: Encrypt characters modulo 3
    for i in range(3, len(flag), 4):
        cipher.append(0x80 + (interm[i] + 0x77) / 16)
        cipher.append(0x80 + (interm[i] + 0x77) % 16)

    for c in cipher:
        if c == 256:
            print '[+] Exception! Character with value 256!'
            return None

    return cipher

# --------------------------------------------------------------------------------------------------
# Main compiler routine.
#
if __name__ == "__main__":
    flag = 'CTF{I_h47e_0n1oNs_&_oNi0n_b1nARi3zzz}'
    cipher = encrypt(flag)

    print '[+] Cipher:', [hex(x) for x in cipher]

# --------------------------------------------------------------------------------------------------
'''
ispo@nogirl:~/ctf/secret_repo/the_onion_binary$ ./flag_encryptor.py
[+] Intermediate: [
    '0x68', '0xda', '0x85', '0x3d', '0xfe', '0xad', '0x60', '0xed',
    '0xff', '0x81', '0xdf', '0x1b', '0x69', '0x75', '0x11', '0x3a',
    '0x15', '0x81', '0x89', '0x73', '0xc4', '0xaa', '0x63', '0x12',
    '0x89', '0x6a', '0xc2', '0xce', '0xc0', '0x41', '0xa1', '0xd'
]

[+] Cipher: [
    '0x3c', '0xdb', '0x7a', '0x7f', '0xb8', '0x78', '0xf8', '0x98',
    '0xe4', '0xca', '0xbc', '0x2c', '0xbc', '0xa6', '0xa9', '0xbf',
    '0x2e', '0x09', '0x88', '0xba', '0x32', '0x0c', '0x6b', '0x4a',
    '0x8b', '0x84', '0x96', '0x84', '0x89', '0x82', '0x8b', '0x81',
    '0x8e', '0x8a', '0x88', '0x89', '0x94', '0x85', '0x88', '0x84']
'''
# --------------------------------------------------------------------------------------------------
