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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import math
import random

import buff
import huffman
import mbrotli

RANDOM_ALPHABET = 'abc'
# Divide the sizes by this. This allows easy scaling up and down of the output.
# A value of 10 means the output would be 100TB/10 = 10TB.
DIVIDER = 1
FIRST_LENGTH = 32392447384365  # 32TB
SECOND_LENGTH = 40184926749268  # 40TB
TOTAL_LENGTH = 100000000000000  # 100TB
MAX_CHARACTER_REPEAT = 100000000000  # every 100GB

FIRST_LENGTH //= DIVIDER
SECOND_LENGTH //= DIVIDER
TOTAL_LENGTH //= DIVIDER
THIRD_LENGTH = TOTAL_LENGTH - FIRST_LENGTH - SECOND_LENGTH
# Don't scale down MAX_CHARACTER_REPEAT linearly, because that leads to large
# bloated files that have only a tiny amount of data in each metablock.
# But after scaling down slowly for a while, the scale down needs to speed up so
# that it remains smaller than FIRST_LENGTH.
MAX_CHARACTER_REPEAT = min(MAX_CHARACTER_REPEAT//int(math.sqrt(DIVIDER)),
                           FIRST_LENGTH//2)
assert 0 < MAX_CHARACTER_REPEAT < FIRST_LENGTH < TOTAL_LENGTH
assert 0 < MAX_CHARACTER_REPEAT < SECOND_LENGTH < TOTAL_LENGTH
assert 0 < MAX_CHARACTER_REPEAT < THIRD_LENGTH < TOTAL_LENGTH

# Returns a number in [5,maximum] unless that's impossible (due to an empty
# range) in which case returns maximum.
# The purpose of randomly reducing is to avoid repetition in the output. It's
# weighted toward returning maximum to reduce overhead bloat.
def WeightedRandReduce(maximum):
  assert maximum > 0
  if random.randrange(5) > 0:
    return maximum
  v = maximum // random.choice([1, 1, 1, 1, 1, 2, 3, 4, 7, 100])
  v -= random.choice([0, 0, 0, 0, 1, 2, 3, 4, 100])
  if v < 5:
    return maximum
  return v

# Put num (a bit_width-bit number) into the OutBitBuff out_buf little endianly.
def PutNum(out_buf, num, bit_width):
  assert 0 <= bit_width <= 64
  while bit_width > 0:
    out_buf.PutBit(num & 1)
    num >>= 1
    bit_width -= 1
  assert num == 0

# Given a value encoded with a prefix encoding, put it into the OutBitBuff
# out_buf. code must be given least significant bit first and whitespace will
# be stripped.
def PutCodedElement(out_buf, code):
  code = code.strip()
  assert set(code) <= set('01')
  for b in code[::-1]:
    out_buf.PutBit(int(b))

# Write MNIBBLES and MLEN into the OutBitBuff out_buf.
def PutMLEN(out_buf, MLEN):
  assert MLEN >= 0
  if MLEN == 0:
    PutCodedElement(out_buf, mbrotli.MNIBBLES_encoder[0])
    # MLEN isn't explicitly written
    return

  MLEN_m_1 = MLEN - 1
  MNIBBLES = (MLEN_m_1.bit_length() + 3)//4
  assert MNIBBLES <= 6
  if MNIBBLES < 4:
    MNIBBLES = 4
  PutCodedElement(out_buf, mbrotli.MNIBBLES_encoder[MNIBBLES])
  PutNum(out_buf, MLEN_m_1, MNIBBLES*4)

# Put an uncompressed metablock containing data into the OutBitBuff out_buf.
def PutUncompressedMetaBlock(out_buf, data):
  assert len(data) > 0
  out_buf.PutBit(0)  # ISLAST
  PutMLEN(out_buf, len(data))
  out_buf.PutBit(1)  # ISUNCOMPRESSED
  out_buf.ByteAlign()
  out_buf.PutBytes(data)

# Put a prefix code (an entire huffman tree) into the OutBitBuff out_buf. This
# is not to be confused with a prefix-coded element.
# Only simple prefix codes are implemented, and only ones with 1, 2 or 3
# symbols. The symbols are put in the block in order as given. This means the
# order matters, except weridly if 3 symbols, the middle and last ones' order
# doesn't matter for encoding/decoding, even though the encoded file is
# different.
def PutPrefixCode(out_buf, symbols, alphabet_size):
  assert alphabet_size > 0
  assert len(symbols) == len(set(symbols))
  NSYM = len(symbols)
  assert 1 <= NSYM <= 3
  ALPHABET_BITS = (alphabet_size-1).bit_length()
  PutNum(out_buf, 1, 2)  # simple prefix code
  PutNum(out_buf, NSYM-1, 2)
  for symbol in symbols:
    assert 0 <= symbol < alphabet_size
    PutNum(out_buf, symbol, ALPHABET_BITS)

# Put a metablock header into the OutBitBuff out_buf.
# It is compressed, not last, has 1 of each block type, and NPOSTFIX 0.
# The symbols are lists of int at most length 3, and must be ordered to be
# used for a simple prefix code.
# Each distance_code_symbols element must be small enough that extra bits aren't
# needed.
def PutMetaBlockHeader(out_buf, length,
                       literal_symbols,
                       insert_copy_length_symbols,
                       distance_code_symbols,
                       NDIRECT):
  assert length > 0
  assert 0 <= NDIRECT <= 15
  out_buf.PutBit(0)  # ISLAST
  PutMLEN(out_buf, length)
  out_buf.PutBit(0)  # ISUNCOMPRESSED
  out_buf.PutBit(0)  # NBLTYPESL = 1
  out_buf.PutBit(0)  # NBLTYPESI = 1
  out_buf.PutBit(0)  # NBLTYPESD = 1
  PutNum(out_buf, 0, 2)  # NPOSTFIX = 0
  PutNum(out_buf, NDIRECT, 4)
  PutNum(out_buf, 0, 2)  # One context mode: LSB6 (irrelevant)
  out_buf.PutBit(0)  # NTREESL = 1
  out_buf.PutBit(0)  # NTREESD = 1
  PutPrefixCode(out_buf, literal_symbols, 256)
  PutPrefixCode(out_buf, insert_copy_length_symbols, 704)
  PutPrefixCode(out_buf, distance_code_symbols, 16 + NDIRECT + 48)

# Make a huffman encoder for the symbols using the simple prefix code
# method. Only 1-3 symbols are suppored. Symbols must be in the same order as
# will be put in the header (although the middle and last symbols don't matter
# for length 3).
def MakeSimplePrefixEncoder(symbols):
  assert 1 <= len(symbols) <= 3
  if len(symbols) == 1:
    return {symbols[0]: ''}
  elif len(symbols) == 2:
    symbols = sorted(symbols)
    return {symbols[0]: '0', symbols[1]: '1'}
  elif len(symbols) == 3:
    # Having to sort the last 2 element is strange, but the spec does
    # specify (confusingly) to do it.
    symbols = symbols[:1] + sorted(symbols[1:])
    return {symbols[0]: '0', symbols[1]: '01', symbols[2]: '11'}
  assert False, 'bad symbol length'

# Encodes value using the extra bits encoding specified by code_list.
# code_list is a list of (extra_bits, min_val) indexed by code.
# Returns code, extra_val, extra_bits (all ints).
def EncodeWithExtraBits(code_list, value):
  for i, (extra_bits, min_val) in enumerate(code_list):
    assert value >= min_val
    if value <= min_val + (1 << extra_bits) - 1:
      return i, value - min_val, extra_bits
  assert False, 'value couldnt be made'

# Given a list of ILEN and CLEN values, return the symbols and
# a huffman extra bits encoder.
# values is list of pairs (ILEN, CLEN)
# Returns a list of insert_copy_length_symbols (ordered for simple prefix code),
# and a mapping from an element of values to (prefix code, insert extra val,
# insert extra bits, copy extra val, copy extra bits).
# This never uses the implicit distance symbol 0, because supporting that
# increases complexity, and it tends to restrict how large the ILEN and CLEN can
# be.
# Note that the spec often calls insert_copy_length_symbols insert-and-copy
# length codes.
# This function is more general that we currently need, in that it supports
# multiple values, but currently we only ever have values be a 1 element list.
def MakeInsertAndCopyLengthEncoder(values):
  table = [
      [0, 64],
      [128, 192, 384],
      [256, 320, 512],
      [448, 575, 640],
  ]
  # mapping from (ILEN, CLEN) to
  # (insert_copy_length_symbol, insert extra val, insert extra bits, copy extra
  #  val, copy extra bits)
  initial_mapping = {}
  for key in values:
    ILEN, CLEN = key
    insert_length_code, insert_length_extra_val, insert_length_extra_bits = (
        EncodeWithExtraBits(mbrotli.insert_length_codes, ILEN))
    copy_length_code, copy_length_extra_val, copy_length_extra_bits = (
        EncodeWithExtraBits(mbrotli.copy_length_codes, CLEN))
    y = insert_length_code // 8
    x = copy_length_code // 8

    y += 1  # because not distance symbol 0

    insert_copy_length_symbol_bottom = table[y][x]
    insert_copy_length_symbol = (insert_copy_length_symbol_bottom |
                                 (copy_length_code & 0x7) |
                                 ((insert_length_code & 0x7) << 3))
    assert key not in initial_mapping
    initial_mapping[key] = (insert_copy_length_symbol,
                            insert_length_extra_val, insert_length_extra_bits,
                            copy_length_extra_val, copy_length_extra_bits)

  insert_copy_length_symbols = list(set(
      v[0] for v in initial_mapping.itervalues()))
  assert len(insert_copy_length_symbols) <= 3
  random.shuffle(insert_copy_length_symbols)
  insert_copy_length_symbol_encoder = MakeSimplePrefixEncoder(
      insert_copy_length_symbols)

  final_mapping = {}
  for key, initial_value in initial_mapping.iteritems():
    assert key not in final_mapping
    (insert_copy_length_symbol,
     insert_length_extra_val, insert_length_extra_bits,
     copy_length_extra_val, copy_length_extra_bits) = initial_value
    insert_copy_length_prefix = insert_copy_length_symbol_encoder[
        insert_copy_length_symbol]
    final_mapping[key] = (insert_copy_length_prefix,
                          insert_length_extra_val, insert_length_extra_bits,
                          copy_length_extra_val, copy_length_extra_bits)

  return insert_copy_length_symbols, final_mapping

# Put a fully encoded insert and copy length element into the OutBitBuff
# out_buf.
# insert_copy_length_encoder is the encoder mapping created by
# MakeInsertAndCopyLengthEncoder. insert_copy_length is a pair of (ILEN, CLEN).
def PutInsertAndCopyLengthElement(out_buf, insert_copy_length_encoder,
                                  insert_copy_length):
  (insert_copy_length_prefix,
   insert_length_extra_val, insert_length_extra_bits,
   copy_length_extra_val, copy_length_extra_bits) = insert_copy_length_encoder[
       insert_copy_length]
  PutCodedElement(out_buf, insert_copy_length_prefix)
  PutNum(out_buf, insert_length_extra_val, insert_length_extra_bits)
  PutNum(out_buf, copy_length_extra_val, copy_length_extra_bits)

# Put a metablock containing data into the OutBitBuff out_buf.
# The data is simply specified literally. The number of unique bytes in data
# must be at most 3.
def PutLiteralMetaBlock(out_buf, data):
  assert len(data) >= 1

  alphabet = [ord(b) for b in set(data)]
  assert len(alphabet) <= 3
  # If we wanted optimal compression, we would put the most common character
  # first, but we don't really want optimal compression, we want
  # unpredictability to avoid repetition.
  random.shuffle(alphabet)
  literal_encoder = MakeSimplePrefixEncoder(alphabet)

  # CLEN 2 is not really used due to single block used up by literals
  insert_copy_lengths = [(len(data), 2)]
  insert_copy_length_symbols, insert_copy_length_encoder = (
      MakeInsertAndCopyLengthEncoder(insert_copy_lengths))

  NDIRECT = 0
  distances = [0]  # Not really used due to single block used up by literals
  distance_encoder = MakeSimplePrefixEncoder(distances)

  PutMetaBlockHeader(out_buf, len(data),
                     alphabet,
                     insert_copy_length_symbols,
                     distances,
                     NDIRECT)

  PutInsertAndCopyLengthElement(out_buf, insert_copy_length_encoder,
                                (len(data), 2))
  for b in data:
    PutCodedElement(out_buf, literal_encoder[ord(b)])

# Put some metablocks representing data into the OutBitBuff out_buf.
# Uses naive "compression".
def PutSpecifiedData(out_buf, data):
  i = 0
  while i < len(data):
    left = len(data) - i
    length = random.randrange(1, min(left, 3)+1)
    assert 1 <= length <= 3
    assert i + length <= data
    PutLiteralMetaBlock(out_buf, data[i:i+length])
    i += length
  assert i == len(data)

# Put a metablock containing char repeated length times into the OutBitBuff
# out_buf. Sets the last distance to 1.
# It's implemented by putting char literally once, then repeating it length-1
# times.
def PutCharRepeatingMetaBlock(out_buf, char, length):
  assert len(char) == 1
  assert 3 <= length <= mbrotli.max_meta_block_size

  alphabet = [ord(char)]
  literal_encoder = MakeSimplePrefixEncoder(alphabet)

  insert_copy_lengths = [(1, length-1)]
  insert_copy_length_symbols, insert_copy_length_encoder = (
      MakeInsertAndCopyLengthEncoder(insert_copy_lengths))

  NDIRECT = 1
  distances = [16]  # Distance = 1
  distance_encoder = MakeSimplePrefixEncoder(distances)

  PutMetaBlockHeader(out_buf, length,
                     alphabet,
                     insert_copy_length_symbols,
                     distances,
                     NDIRECT)

  PutInsertAndCopyLengthElement(out_buf, insert_copy_length_encoder,
                                (1, length-1))
  PutCodedElement(out_buf, literal_encoder[ord(char)])
  PutCodedElement(out_buf, distance_encoder[16])

# Put a metablock that uses the last distance, and repeats length bytes into the
# OutBitBuff out_buf. Uses no literals.
def PutLargeRepeatingMetaBlock(out_buf, length):
  assert 2 <= length <= mbrotli.max_meta_block_size

  alphabet = [0]  # Not really used
  literal_encoder = MakeSimplePrefixEncoder(alphabet)

  insert_copy_lengths = [(0, length)]
  insert_copy_length_symbols, insert_copy_length_encoder = (
      MakeInsertAndCopyLengthEncoder(insert_copy_lengths))

  NDIRECT = 0
  distances = [0]  # Use last distance
  distance_encoder = MakeSimplePrefixEncoder(distances)

  PutMetaBlockHeader(out_buf, length,
                     alphabet,
                     insert_copy_length_symbols,
                     distances,
                     NDIRECT)

  PutInsertAndCopyLengthElement(out_buf, insert_copy_length_encoder,
                                (0, length))
  PutCodedElement(out_buf, distance_encoder[0])

# Put a metablock that goes back distance bytes, then repeats length bytes
# starting from that point into the OutBitBuff out_buf. Uses no literals.
def PutSpecificRepeatingMetaBlock(out_buf, length, distance):
  assert 2 <= length <= mbrotli.max_meta_block_size
  assert 1 <= distance <= 15

  alphabet = [0]  # Not really used
  literal_encoder = MakeSimplePrefixEncoder(alphabet)

  insert_copy_lengths = [(0, length)]
  insert_copy_length_symbols, insert_copy_length_encoder = (
      MakeInsertAndCopyLengthEncoder(insert_copy_lengths))

  NDIRECT = distance
  distances = [distance+15]
  distance_encoder = MakeSimplePrefixEncoder(distances)

  PutMetaBlockHeader(out_buf, length,
                     alphabet,
                     insert_copy_length_symbols,
                     distances,
                     NDIRECT)

  PutInsertAndCopyLengthElement(out_buf, insert_copy_length_encoder,
                                (0, length))
  PutCodedElement(out_buf, distance_encoder[distance+15])

# Put some metablocks into the OutBitBuff out_buf such that char is repeated
# length times.
# If this will be called multiple times, then it's expected length will already
# have some randomness in it, because this function will not necessarily
# introduce randomness.
def PutRepeatedCharacter(out_buf, char, length):
  assert len(char) == 1
  assert length >= 3
  first_length = min(length, WeightedRandReduce(mbrotli.max_meta_block_size))
  if 0 < length - first_length < 3:
    assert first_length >= 5
    first_length -= 2
  assert 3 <= first_length <= length

  PutCharRepeatingMetaBlock(out_buf, char, first_length)
  i = first_length
  while i < length:
    left = length - i
    this_length = min(left, WeightedRandReduce(mbrotli.max_meta_block_size))
    if 0 < left - this_length < 2:
      assert this_length >= 5
      this_length -= 1
    assert 2 <= this_length <= left < length
    PutLargeRepeatingMetaBlock(out_buf, this_length)
    i += this_length
  assert i == length

# Put length bytes of random compressed junk data into the OutBitBuff out_buf.
# Likely spread across multiple metablocks.
def PutJunkData(out_buf, length):
  assert length >= 3
  i = 0
  while i < length:
    left = length - i
    this_length = min(left, WeightedRandReduce(MAX_CHARACTER_REPEAT))
    if 0 < left - this_length < 3:
      assert this_length >= 5
      this_length -= 2
    assert 3 <= this_length <= left <= length
    PutRepeatedCharacter(out_buf, random.choice(RANDOM_ALPHABET), this_length)
    i += this_length
    print('i {}'.format(i))
  assert i == length

def main():
  random.seed(39837259872983759730382408320981)
  out_buf = buff.OutBitBuff()
  # Use the maximum window size not because we must, but because we can.
  PutCodedElement(out_buf, mbrotli.WBITS_encoder[24])
  PutSpecifiedData(
      out_buf,
      '<html>\n<head><title>Flag page</title></head>\n<body>\nFlag:\n<!--')
  PutJunkData(out_buf, FIRST_LENGTH)
  PutUncompressedMetaBlock(out_buf, 'Keep looking')
  PutJunkData(out_buf, SECOND_LENGTH)
  # CTF{DontEatThePl4yerEatTheBrotli}
  # -- Ice T
  PutSpecifiedData(out_buf, '-->\nCTF{DontEatThePl4yer')
  PutSpecificRepeatingMetaBlock(out_buf, 6, 12)  # repeat 'EatThe'
  PutSpecifiedData(out_buf, 'Brotli}\n<!--')
  PutJunkData(out_buf, THIRD_LENGTH)
  PutSpecifiedData(out_buf, '-->\n</body>\n</html>\n')

  out_buf.PutBit(1)  # ISLAST
  out_buf.PutBit(1)  # ISLASTEMPTY
  out_buf.ByteAlign()

  with open('bomb.br', 'wb') as f:
    f.write(out_buf.GetBytes())

main()
