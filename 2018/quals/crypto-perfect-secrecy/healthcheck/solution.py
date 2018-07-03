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

import bitarray
import collections
import hexdump
import itertools
import logging
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

import eventlet
from eventlet.green import socket

logger = logging.getLogger('healthcheck')


def Int2Bytes(x):
  return x.to_bytes((x.bit_length() + 7) // 8, 'big')


def Bytes2Int(x):
  return int.from_bytes(x, 'big')


def ReadPublicKey(filename):
  return serialization.load_pem_public_key(
      open(filename, 'rb').read(), backend=default_backend())


class Solver(object):

  def __init__(self, public_key_file, ciphertext_file, host, port):
    self.public_key = ReadPublicKey(public_key_file)
    self.ciphertext = Bytes2Int(open(ciphertext_file, 'rb').read())
    self.address = (host, port)

  def DecryptMessage(self, bytes_to_decrypt=None):
    if not bytes_to_decrypt:
      bytes_to_decrypt = self.public_key.key_size // 8
    # c0 = m**e % n
    #
    # -----------------------------------------------------------
    # Multiply c0 by 2**e:
    # c1 = c0*2**e % n = (2m)**e % n
    # Two possibilities:
    #
    # m < n/2 => (2m) doesn't wrap n => oracle says d(c1) is even
    #
    # m >= n/2 => (2m) wraps n => 2m = n + t
    #          => 2m = n + t (mod 2)
    #          => 0 = 1 (because 2 doesn't divide n) + 1 (has to be 1 for mod2
    #                                                     equation to hold)
    #          => oracle says d(c1) is odd
    #
    # Conversely:
    # oracle syas d(c1) is even => m < n/2
    # oracle syas d(c1) is odd => m >= n/2
    #
    # -----------------------------------------------------------
    # Same for c2: multiply c0 by 4**e:
    # c2 = c0*4**e % n = (4m)**e % n
    # Two possibilities:
    #
    # m < n/4 => (4m) doesn't wrap n => oracle says d(c1) is even
    #
    # m >= n/4 => (4m) wraps n => 4m = n + t
    #          => 4m = n + t (mod 2)
    #          => 0 = 1 (because 2 doesn't divide n) + 1 (has to be 1 for mod2
    #                                                     equation to hold)
    #          => oracle says d(c1) is odd
    #
    # Conversely:
    # oracle syas d(c1) is even => m < n/4
    # oracle syas d(c1) is odd => m >= n/4
    #
    # -----------------------------------------------------------
    # Maintain a range of possible m values, starting with [0, n].
    # Each iteration halves the range.
    #
    c0 = self.ciphertext
    low = 0
    high = self.public_key.public_numbers().n

    bit_at = self.public_key.key_size - 1
    result = bitarray.bitarray()

    # Loop invarients:
    # low <= plaintext m <= high
    # result holds the highest bits of m: the highest (key_size - bit_at bits)
    # common bits of low and high.
    for i in itertools.count(1):
      # logging.info('Iteration: %d', i)
      # logging.info('Low:\n%s', hexdump.hexdump(Int2Bytes(low), result='return'))
      # logging.info('High:\n%s', hexdump.hexdump(Int2Bytes(high), result='return'))

      ci = pow(2**i,
               self.public_key.public_numbers().e,
               self.public_key.public_numbers().n)
      ci = (ci * c0) % self.public_key.public_numbers().n
      is_even = self.ParityOracle(ci)
      if is_even:
        high -= (high - low) // 2
      else:
        low += (high - low) // 2

      # low and high agree on a MSBs -> we've just learned a new bit of m.
      if bool(low & (1 << bit_at)) == bool(high & (1 << bit_at)):
        result.append(high & (1 << bit_at))
        bit_at -= 1
        # logging.debug('Top m bits: %s', result)

      if (high - low) < 2 or result.length() == bytes_to_decrypt * 8:
        break

    return result.tobytes()

  def SingleExperiment(self, m0, m1, dice):
    conn = socket.create_connection(self.address)
    conn.send(m0)
    conn.send(m1)
    conn.send(dice)
    result = b''
    while len(result) < 100:
      result += conn.recv(100-len(result))
    return result

  def ParityOracle(self, c):
    m0 = b'\x00'
    m1 = b'\x01'
    c = c.to_bytes(self.public_key.key_size // 8, 'big')
    counts = collections.Counter()

    # k chosen uniformly from K = {0, 1, 2}
    # result (mi + k) mod 2 leaks data on the plaintext mi:
    # since K = {0, 1, 0} mod 2, the value k=0 is twice as likely
    # to be chosen than k=1, and therefore, the chosen plaintext mi
    # is twice as likely to appear in the result.
    # Run the experiment until it's statistically significant that we
    # know which mi was chosen.
    ratio = 0
    while ratio < 0.64:
      counts.update(self.SingleExperiment(m0, m1, c))
      ratio = counts.most_common()[0][1] / sum(counts.values())
      # logging.debug('Counts: %s. Ratio: %f', counts, ratio)

    return counts.get(0, 0) > counts.get(1, 0)


def main(argv):
  logging.basicConfig(level=logging.DEBUG)
  solver = Solver(*argv[1:])
  solver.DecryptMessage()


if __name__ == '__main__':
  sys.exit(main(sys.argv))
