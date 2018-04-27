#!/usr/bin/python
#
# Copyright 2018 Google LLC
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
from binascii import unhexlify, hexlify
from hashlib import md5

def string_to_int (string):
    out = 0
    for c in string:
        out <<= 8
        out |= ord(c)
    return out

def int_to_string (integer):
    out = ""
    while (integer > 0):
        out = chr(integer & 0xFF) + out
        integer >>= 8
    return out


class ZXHash():
    #Should be 16 bytes, hex encoded
    key1 = None
    #Should be large and prime
    key2 = None

    def __init__(self, key1, key2):
        self.key1 = key1
        self.key2 = key2

    def hash(self, inp):
        string = self.key1 + inp
        string = string + (64 - len(string)%64)*"0"

        value = int(string, 16)

        s = 0

        while (value > 0):
            s = s ^ (value & (pow(2, 256) - 1))
            value = value >> 256

        b4 = s & pow(2,64)-1
        s = s >> 64
        b3 = s & pow(2,64)-1
        s = s >> 64
        b2 = s & pow(2,64)-1
        s = s >> 64
        b1 = s & pow(2,64)-1


        hsh = md5(int_to_string(b4)).digest()[:8]
        m = string_to_int(hsh)
        b3 = b3 % m
        e = pow(self.key2, 128+b3, m)
        return hex((b1 ^ b2 ^ e) % m)[2:-1]
