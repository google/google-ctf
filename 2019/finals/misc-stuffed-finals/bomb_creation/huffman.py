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

import buff

# This class implements huffman tree encoding an decoding.
# The huffman trees use a simple representation of nested lists where each list
# is length 2. A lack of values is represented by None. This representation
# means the actual values stored in the tree cannot be list or None.
# All codes must be 01 strings with least significant bit first. Whitespace is
# ignored.

# Insert v in to tree at the location specified by code.
# That location must be empty to start with.
def InsertInTree(tree, code, v):
  assert len(code) > 0
  assert v is not None
  assert type(v) is not list
  assert len(tree) == 2
  loc = int(code[-1])
  if len(code) == 1:
    assert tree[loc] is None
    tree[loc] = v
    return
  if tree[loc] is None:
    tree[loc] = [None]*2
  InsertInTree(tree[loc], code[:-1], v)

# pairs is a list of (value, code) pairs. Order doesn't matter.
# The values must not be list or None.
def MakeTreeFromPairs(pairs):
  assert pairs
  if len(pairs) == 1:
    v, code = pairs[0]
    assert code == ''
    assert type(v) is not list
    return v
  res = [None]*2
  for v, code in pairs:
    assert type(v) is not list
    code = code.strip()
    InsertInTree(res, code, v)
  return res

def PrintTree(tree, indent=0):
  s = ' '*indent
  if type(tree) is not list:
    print(s + repr(tree))
    return
  print(s + '[')
  for n in tree:
    PrintTree(n, indent+2)
  print(s + ']')

# Read bits from the InBitBuff in_bits to decode one element using tree.
def ReadCodedElement(in_bits, tree):
  while type(tree) is list:
    tree = tree[in_bits.ReadBit()]
  assert tree is not None
  return tree
