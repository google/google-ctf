#!/usr/bin/python3

# Copyright 2022 Google LLC
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

"""
It is well known that any RSA encryption can be undone by just encrypting the
ciphertext over and over again. If the RSA modulus has been chosen badly then
the number of encryptions necessary to undo an encryption is small.
If n = 0x112b00148621 then only 209 encryptions are necessary as the following
example demonstrates:

>>> e = 65537
>>> n = 0x112b00148621
>>> pt = 0xdeadbeef
>>> # Encryption
>>> ct = pow(pt, e, n)
>>> # Decryption via cycling:
>>> pt = ct
>>> for _ in range(209):
>>>   pt = pow(pt, e, n)
>>> # Assert decryption worked:
>>> assert ct == pow(pt, e, n)

However, if the modulus is well chosen then a cycle attack can take much longer.
This property can be used for a timed release of a message. We have confirmed
that it takes a whopping 2^1025-3 encryptions to decrypt the flag. Pack out
your quantum computer and perform 2^1025-3 encryptions to solve this
challenge. Good luck doing this in 48h.
"""

e = 65537
n = 0x99efa9177387907eb3f74dc09a4d7a93abf6ceb7ee102c689ecd0998975cede29f3ca951feb5adfb9282879cc666e22dcafc07d7f89d762b9ad5532042c79060cdb022703d790421a7f6a76a50cceb635ad1b5d78510adf8c6ff9645a1b179e965358e10fe3dd5f82744773360270b6fa62d972d196a810e152f1285e0b8b26f5d54991d0539a13e655d752bd71963f822affc7a03e946cea2c4ef65bf94706f20b79d672e64e8faac45172c4130bfeca9bef71ed8c0c9e2aa0a1d6d47239960f90ef25b337255bac9c452cb019a44115b0437726a9adef10a028f1e1263c97c14a1d7cd58a8994832e764ffbfcc05ec8ed3269bb0569278eea0550548b552b1
ct = 0x339be515121dab503106cd190897382149e032a76a1ca0eec74f2c8c74560b00dffc0ad65ee4df4f47b2c9810d93e8579517692268c821c6724946438a9744a2a95510d529f0e0195a2660abd057d3f6a59df3a1c9a116f76d53900e2a715dfe5525228e832c02fd07b8dac0d488cca269e0dbb74047cf7a5e64a06a443f7d580ee28c5d41d5ede3604825eba31985e96575df2bcc2fefd0c77f2033c04008be9746a0935338434c16d5a68d1338eabdcf0170ac19a27ec832bf0a353934570abd48b1fe31bc9a4bb99428d1fbab726b284aec27522efb9527ddce1106ba6a480c65f9332c5b2a3c727a2cca6d6951b09c7c28ed0474fdc6a945076524877680
# Decryption via cycling:
pt = ct
for _ in range(2**1025 - 3):
  pt = pow(pt, e, n)
# Assert decryption worked:
assert ct == pow(pt, e, n)

# Print flag:
print(pt.to_bytes((pt.bit_length() + 7)//8, 'big').decode())
