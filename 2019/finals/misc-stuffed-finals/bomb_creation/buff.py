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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

# Given a string, read the bits from it, starting at the least significant bit
# of the first byte.
class InBitBuff(object):
  def __init__(self, s):
    self._s = s
    self._i = 0

  def ReadBit(self):
    byte = ord(self._s[self._i//8])
    bit = (byte >> (self._i%8)) & 1
    self._i += 1
    return bit

  # Read n bytes (must be already byte-aligned).
  def ReadBytes(self, n):
    assert self._i % 8 == 0
    bytei = self._i//8
    assert bytei < len(self._s)
    assert bytei+n <= len(self._s)
    self._i += n*8
    return self._s[bytei:bytei+n]

  # Return the number of bits that need to be read until we're byte-aligned.
  def TillBoundary(self):
    return (-self._i) % 8

  # The number of bits read from the buff.
  def BitsRead(self):
    return self._i

  # The total number of unread bits.
  def BitsLeft(self):
    return len(self._s)*8 - self._i

class OutByteBuff(object):
  def __init__(self):
    self._l = []

  def PutByte(self, b):
    assert len(b) == 1
    self._l.append(b)

  # Go back back bytes, and copy n bytes starting there.
  # Note that n can be larger than back, meaning bytes will be repeated multiple
  # times.
  def CopyNFromBack(self, n, back):
    assert n > 0
    assert 0 < back <= len(self._l)
    for i in xrange(n):
      self._l.append(self._l[-back])

  def GetBytes(self):
    return ''.join(self._l)

# Write bits into a buffer that can be read as a string. Bits are written least
# significant bit first.
class OutBitBuff(object):
  def __init__(self):
    self._l = []
    self._num = 0
    self._i = 0

  def PutBit(self, b):
    assert b == 0 or b == 1
    self._num |= (b << self._i)
    self._i = (self._i+1) % 8
    if self._i == 0:
      self._l.append(self._num)
      self._num = 0

  # Write 0 bits until we're byte-aligned.
  def ByteAlign(self):
    while self._i != 0:
      self.PutBit(0)

  # Must be already byte-aligned.
  def PutBytes(self, data):
    assert self._i == 0
    assert self._num == 0
    self._l += [ord(b) for b in data]

  # Must be already byte-aligned.
  def GetBytes(self):
    assert self._i == 0
    assert self._num == 0
    return ''.join(chr(x) for x in self._l)

  def BitLen(self):
    return len(self._l)*8 + self._i
