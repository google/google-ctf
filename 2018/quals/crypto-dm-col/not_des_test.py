#!/usr/bin/env python3
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

from not_des import *

import unittest
import random


class TestDES(unittest.TestCase):

  def testStr2Bits(self):
    self.assertEqual([0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0],
                     Str2Bits(b'\x12\xfc'))

  def testBits2Str(self):
    self.assertEqual(Bits2Str(Str2Bits(b'\x11\x22\x33')), b'\x11\x22\x33')

  def testEncryption(self):
    # Test vector copied from http://cryptomanager.com/tv.html.
    plaintext = b'\x11\x22\x33\x44\x55\x66\x77\x88'
    key = b'\x75\x28\x78\x39\x74\x93\xCB\x70'
    ciphertext = b'\x30\x55\x5e\x42\x11\x6c\xa8\xda'
    self.assertEqual(DESEncrypt(plaintext, key), ciphertext)
    self.assertEqual(DESDecrypt(ciphertext, key), plaintext)

  def testWeakKeys(self):
    # Key scheudler is just shifts and permutations of the master key.
    # Therefore, an all zeros master key produces all zeros round keys.
    weak1 = Str2Bits(b'\x00\x00\x00\x00\x00\x00\x00\x00')
    expected = [0] * 48
    self.assertTrue(all([expected == ki for ki in KeyScheduler(weak1)]))
    # DESDecrypt is equal to DESEncrypt with round keys in reverse order.
    # Therefore, if all round keys are zeros, DESEncrypt is equal to DESDecrypt.
    plaintext = b'\x11\x22\x33\x44\x55\x66\x77\x88'
    self.assertEqual(DESEncrypt(DESEncrypt(plaintext, weak1), weak1), plaintext)

  def testFixedPoint(self):
    # Generate the same, all zeros, round keys.
    weak_key = Str2Bits(b'\x00\x00\x00\x00\x00\x00\x00\x00')

    # 8 Rounds feistel network, starting with L=R.
    L = [random.choice([0, 1]) for i in range(32)]
    R = L
    for i, ki in enumerate(KeyScheduler(weak_key)):
      L, R = R, Xor(L, CipherFunction(ki, R))
      if i == 7:
        break

    # Final permutation.
    plaintext = Concat(R, L)
    plaintext = [plaintext[IP_INV[i] - 1] for i in range(64)]

    # Verify we found a fixed point.
    ciphertext = DESEncrypt(plaintext, weak_key)
    ciphertext = Str2Bits(ciphertext)
    self.assertEqual(plaintext, ciphertext)

  def testDaviesMeyerCollision(self):
    # Fixed points copied from TestFixedPoint above.
    weak_key = b'\x00\x00\x00\x00\x00\x00\x00\x00'
    fp1 = b'\xf9\x82\x37\x02\x8c\xd4\xfd\x20'
    fp2 = b'\xe7\x53\x19\x49\x7d\x66\x0b\x7d'
    self.assertEqual(fp1, DESEncrypt(fp1, weak_key))
    self.assertEqual(fp2, DESEncrypt(fp2, weak_key))

    def H(k, x):
      assert (isinstance(k, bytes) and len(k) == 8)
      assert (isinstance(x, bytes) and len(x) == 8)
      return Bits2Str(Xor(Str2Bits(DESEncrypt(x, k)), Str2Bits(x)))

    self.assertEqual(H(weak_key, fp1), b'\x00' * 8)
    self.assertEqual(H(weak_key, fp2), b'\x00' * 8)
    self.assertTrue(H(weak_key, fp1) == H(weak_key, fp2) and fp1 != fp2)


if __name__ == '__main__':
  unittest.main()
