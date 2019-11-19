#!/usr/bin/python2

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

# Decompress a brotli file. Use --only_short to solve the challenge.

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse

import buff
import huffman
import mbrotli

# Read a bit_width-bits little endian number from the InBitBuff in_bits.
def ReadNum(in_bits, bit_width):
  val = 0
  for i in xrange(bit_width):
    val |= in_bits.ReadBit() << i
  return val

# Read MNIBBLES from the InBitBuff in_bits.
def ReadMNIBBLES(in_bits):
  # The prefix code bits are read most significant bit first, but mbrotli has
  # them least significant bit first.
  msb = in_bits.ReadBit()
  lsb = in_bits.ReadBit()
  return mbrotli.MNIBBLES_decoder[str(lsb) + str(msb)]

# Read MLEN from the InBitBuff in_bits.
def ReadMLEN(in_bits, MNIBBLES):
  num_bits = MNIBBLES*4
  val = ReadNum(in_bits, num_bits)
  if MNIBBLES > 4:
    assert val >= 1<<(num_bits-4)
  return val + 1

# Read NBLTYPES from the InBitBuff in_bits. Always positive.
# Also useful for values sharing the same structure.
def ReadNBLTYPES(in_bits):
  v_bottom, num_bits = huffman.ReadCodedElement(in_bits,
                                                mbrotli.NBLTYPES_huffman)
  return v_bottom + ReadNum(in_bits, num_bits)

# Read all the context modes from the InBitBuff in_bits.
def ReadContextModes(in_bits, NBLTYPESL):
  return [ReadNum(in_bits, 2) for _ in xrange(NBLTYPESL)]

# Read a prefix code (an entire huffman tree) from the InBitBuff in_bits.
# Only simple prefix trees are supported. Returns the huffman tree.
def ReadPrefixCode(in_bits, alphabet_size):
  two_bits = ReadNum(in_bits, 2)
  if two_bits != 1:
    assert False, 'complex prefix trees not supported'
  NSYM = ReadNum(in_bits, 2) + 1
  assert alphabet_size >= 1
  ALPHABET_BITS = (alphabet_size-1).bit_length()
  symbols = [ReadNum(in_bits, ALPHABET_BITS) for i in xrange(NSYM)]
  if NSYM == 1:
    return symbols[0]
  elif NSYM == 2:
    lengths = [1, 1]
    symbols = sorted(symbols)
  elif NSYM == 3:
    lengths = [1, 2, 2]
    symbols = symbols[:1] + sorted(symbols[1:])
  else:
    assert NSYM == 4
    tree_select = in_bits.ReadBit()
    if tree_select == 0:
      lengths = [2, 2, 2, 2]
      symbols = sorted(symbols)
    else:
      assert tree_select == 1
      lengths = [1, 2, 3, 3]
      symbols = symbols[:2] + sorted(symbols[2:])
  assert len(lengths) == NSYM

  MAX_BITS = max(lengths)
  bl_count = [0]*(MAX_BITS+1)
  for length in lengths:
    bl_count[length] += 1

  code = 0
  assert bl_count[0] == 0
  next_code = [None]*(MAX_BITS+1)
  for bits in xrange(1, MAX_BITS+1):
    code = (code + bl_count[bits-1]) << 1
    next_code[bits] = code

  numeric_codes = [None]*NSYM
  for n in xrange(NSYM):
    l = lengths[n]
    if l != 0:
      numeric_codes[n] = next_code[l]
      next_code[l] += 1

  pairs = [
      (symbol, format(numeric_code, '0{}b'.format(l))[::-1]) for
       symbol, numeric_code, l in zip(symbols, numeric_codes, lengths)
  ]
  return huffman.MakeTreeFromPairs(pairs)

# Reads an insert and copy length element from the InBitBuff in_bits.
# Returns ILEN, CLEN, distance_symbol_0
def ComputeInsertAndCopyLength(in_bits, insert_copy_length_symbol):
  distance_symbol_0 = False
  if insert_copy_length_symbol <= 63:
    assert insert_copy_length_symbol >= 0
    distance_symbol_0 = True
    insert_length_code_start = 0
    copy_length_code_start = 0
  elif insert_copy_length_symbol <= 127:
    distance_symbol_0 = True
    insert_length_code_start = 0
    copy_length_code_start = 8
  elif insert_copy_length_symbol <= 191:
    insert_length_code_start = 0
    copy_length_code_start = 0
  elif insert_copy_length_symbol <= 255:
    insert_length_code_start = 0
    copy_length_code_start = 8
  elif insert_copy_length_symbol <= 319:
    insert_length_code_start = 8
    copy_length_code_start = 0
  elif insert_copy_length_symbol <= 383:
    insert_length_code_start = 8
    copy_length_code_start = 8
  elif insert_copy_length_symbol <= 447:
    insert_length_code_start = 0
    copy_length_code_start = 16
  elif insert_copy_length_symbol <= 511:
    insert_length_code_start = 16
    copy_length_code_start = 0
  elif insert_copy_length_symbol <= 575:
    insert_length_code_start = 8
    copy_length_code_start = 16
  elif insert_copy_length_symbol <= 639:
    insert_length_code_start = 16
    copy_length_code_start = 8
  elif insert_copy_length_symbol <= 703:
    insert_length_code_start = 16
    copy_length_code_start = 16
  else:
    assert False, 'bad insert_copy_length_symbol'
  bottom_6 = insert_copy_length_symbol & 0x3f
  insert_length_code = insert_length_code_start + (bottom_6 >> 3)
  copy_length_code = copy_length_code_start + (bottom_6 & 0x7)
  insert_length_extra_bits, insert_length_start = mbrotli.insert_length_codes[
      insert_length_code]
  copy_length_extra_bits, copy_length_start = mbrotli.copy_length_codes[
      copy_length_code]
  ILEN = insert_length_start + ReadNum(in_bits, insert_length_extra_bits)
  CLEN = copy_length_start + ReadNum(in_bits, copy_length_extra_bits)
  return ILEN, CLEN, distance_symbol_0

# A class to track the most recently used distances.
class LastDistances(object):
  def __init__(self):
    self.b = [16, 15, 11, 4]
    self.i = 3

  # Indicate that the distance dist was just used.
  def Push(self, dist):
    assert dist > 0
    self.i += 1
    self.i %= 4
    self.b[self.i] = dist

  # Get the distance that happened back ago.
  def GetPrevious(self, back):
    assert 0 < back <= 4
    index = (self.i - (back - 1)) % 4
    return self.b[index]

# Given a distance symbol, compute what distance should be used.
# NPOSTFIX must be 0, and distance_symbol must be small enough that extra bits
# aren't needed.
def ComputeDistance(distance_symbol, last_distance, NDIRECT):
  assert 0 <= distance_symbol <= 15 + NDIRECT
  assert 0 <= NDIRECT <= 15  # NDIRECT > 15 not implemented
  d = ComputeDistanceInternal(distance_symbol, last_distance, NDIRECT)
  assert d > 0
  return d

# A helper for ComputeDistance
def ComputeDistanceInternal(distance_symbol, last_distances, NDIRECT):
  if distance_symbol == 0:
    return last_distances.GetPrevious(1)
  elif distance_symbol == 1:
    return last_distances.GetPrevious(2)
  elif distance_symbol == 2:
    return last_distances.GetPrevious(3)
  elif distance_symbol == 3:
    return last_distances.GetPrevious(4)
  elif distance_symbol == 4:
    return last_distances.GetPrevious(1) - 1
  elif distance_symbol == 5:
    return last_distances.GetPrevious(1) + 1
  elif distance_symbol == 6:
    return last_distances.GetPrevious(1) - 2
  elif distance_symbol == 7:
    return last_distances.GetPrevious(1) + 2
  elif distance_symbol == 8:
    return last_distances.GetPrevious(1) - 3
  elif distance_symbol == 9:
    return last_distances.GetPrevious(1) + 3
  elif distance_symbol == 10:
    return last_distances.GetPrevious(2) - 1
  elif distance_symbol == 11:
    return last_distances.GetPrevious(2) + 1
  elif distance_symbol == 12:
    return last_distances.GetPrevious(2) - 2
  elif distance_symbol == 13:
    return last_distances.GetPrevious(2) + 2
  elif distance_symbol == 14:
    return last_distances.GetPrevious(2) - 3
  elif distance_symbol == 15:
    return last_distances.GetPrevious(2) + 3
  v = distance_symbol - 15
  assert 0 < v <= NDIRECT
  return v

# Reads from the InBitBuff in_bits until it's byte aligned, and verifies all
# read bits are 0.
def ReadCheckTillBoundary(in_bits):
  while in_bits.TillBoundary() != 0:
    ignored_bit = in_bits.ReadBit()
    assert ignored_bit == 0

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument("in_file")
  parser.add_argument("out_file")
  parser.add_argument("--only_short", help="Only decompress short metablocks",
                      action="store_true")
  args = parser.parse_args()
  with open(args.in_file, 'rb') as f:
    in_bits = buff.InBitBuff(f.read())

  WBITS = huffman.ReadCodedElement(in_bits, mbrotli.WBITS_huffman)
  window_size = (1 << WBITS) - 16

  result = buff.OutByteBuff()
  last_distances = LastDistances()
  last_print_at = 0
  while True:
    ISLAST = in_bits.ReadBit()
    if ISLAST:
      ISLASTEMPTY = in_bits.ReadBit()
      if ISLASTEMPTY:
        print('ISLASTEMPTY')
        ReadCheckTillBoundary(in_bits)
        break
    MNIBBLES = ReadMNIBBLES(in_bits)
    if not MNIBBLES:
      assert in_bits.ReadBit() == 0
      assert False, 'MSKIPLEN not implemented'
    MLEN = ReadMLEN(in_bits, MNIBBLES)
    short = MLEN <= 50
    if not ISLAST:
      ISUNCOMPRESSED = in_bits.ReadBit()
      if ISUNCOMPRESSED:
        ReadCheckTillBoundary(in_bits)
        for c in in_bits.ReadBytes(MLEN):
          if short or not args.only_short:
            result.PutByte(c)
        continue

    for _ in range(3):  # loop for each three block categories (i = L, I, D)
      NBLTYPESi = ReadNBLTYPES(in_bits)
      assert NBLTYPESi == 1, 'NBLTYPESi >= 2 not implemented'
      # Thus BTYPE_i = 0 and BLEN_i = 16777216

    NPOSTFIX = ReadNum(in_bits, 2)
    assert NPOSTFIX == 0
    NDIRECT_top = ReadNum(in_bits, 4)
    NDIRECT = NDIRECT_top << NPOSTFIX
    # returns CMODE but we don't need it
    ReadContextModes(in_bits, 1)  # NBLTYPESL is 1
    NTREESL = ReadNBLTYPES(in_bits)
    if NTREESL != 1:
      assert False, 'literal context map not implemented'
    # CMAPL = [0]*(64*NBLTYPESL) but not needed
    NTREESD = ReadNBLTYPES(in_bits)
    if NTREESD != 1:
      assert False, 'distance context map not implemented'
    # CMAPD = [0]*(4*NBLTYPESD) but not needed
    # It's known that NTREESL, NBLTYPESI, NTREESD are 1, so these are 1-element
    # lists respectively.
    HTREEL = [ReadPrefixCode(in_bits, 256)]
    HTREEI = [ReadPrefixCode(in_bits, 704)]
    HTREED = [ReadPrefixCode(in_bits, 16 + NDIRECT + (48 << NPOSTFIX))]

    bytes_produced_in_meta_block = 0
    while True:
      # Don't bother decrementing/checking BLEN_I because it's huge.
      # We know there's only one possible BTYPE_I value: 0.
      insert_copy_length_symbol = huffman.ReadCodedElement(in_bits, HTREEI[0])
      ILEN, CLEN, distance_symbol_0 = ComputeInsertAndCopyLength(
          in_bits, insert_copy_length_symbol)
      for i in xrange(ILEN):
        # Don't bother decrementing/checking BLEN_L because it's huge.
        # Every element of CMAPL is 0, so there's no need to use CMODE and
        # BTYPE_L to find context mode to find context ID and CIDL.
        literal = huffman.ReadCodedElement(in_bits, HTREEL[0])
        if short or not args.only_short:
          result.PutByte(chr(literal))
        bytes_produced_in_meta_block += 1
      if bytes_produced_in_meta_block == MLEN:
        break
      assert bytes_produced_in_meta_block < MLEN

      if distance_symbol_0:
        backward_distance = last_distances.GetPrevious(1)
      else:
        # Don't bother decrementing/checking BLEN_D because it's huge.
        # Every element of CMAPD is 0, so there's no need to compute context ID,
        # CIDD from CLEN.
        distance_symbol = huffman.ReadCodedElement(in_bits, HTREED[0])
        backward_distance = ComputeDistance(distance_symbol, last_distances,
                                            NDIRECT)
        if distance_symbol != 0:
          assert backward_distance < window_size + 1, (
              'static dictionary not supported')
          last_distances.Push(backward_distance)

      assert backward_distance > 0
      if backward_distance < window_size + 1:
        if short or not args.only_short:
          result.CopyNFromBack(CLEN, backward_distance)
        bytes_produced_in_meta_block += CLEN
      else:
        assert False, 'static dictionary not supported'
      if bytes_produced_in_meta_block == MLEN:
        break
    assert bytes_produced_in_meta_block == MLEN
    if ISLAST:
      print('End of ISLAST metablock')
      ReadCheckTillBoundary(in_bits)
      break
    if short and args.only_short:
      print(result.GetBytes())
    if in_bits.BitsRead() > last_print_at + 1000000:
      print('Bits read: {}'.format(in_bits.BitsRead()))
      last_print_at = in_bits.BitsRead()
  print('All done')
  assert in_bits.TillBoundary() == 0
  assert in_bits.BitsLeft() == 0
  with open(args.out_file, 'wb') as fo:
    fo.write(result.GetBytes())

main()
