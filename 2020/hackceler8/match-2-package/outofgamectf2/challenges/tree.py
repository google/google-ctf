# Copyright 2020 Google LLC
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
import random
import struct
import os

banner = """
Your task is to find the min and max value from a binary tree as well as the count of leaf nodes.
rdi points to a rw mapping with the following data:
  u64 root
  struct(
    union {
      u64 left
      u64 leaf_node_marker
    }
    union {
      u64 right
      u64 value
    }
  } nodes[...]
root, left and right are indexes into the nodes array.
a node is either a leaf node or a tree node:
- a tree node has left and right values != ~0
- a leaf node has the first u64 == ~0 and the second contains the value
write the min, max and leaf count u64 in little endian binary to stdout.
"""

flag = "HCL8{tr3Es_Are_f_u_N}"

class Node(object):
  def __init__(self, value, left=None, right=None):
    self.value = value
    self.left = left
    self.right = right
    assert((self.left is None) == (self.right is None))
    assert((self.value is None) != (self.left is None))

  def __str__(self):
    return "(%s,%s)" % (str(self.left), str(self.right)) if self.value is None else str(self.value)
  def __repr__(self):
    return str(self)

  def serialize(self, offset=0):
    if self.value is not None:
      return [Node(self.value)]
    offset += 1
    l = self.left.serialize(offset)
    r = self.right.serialize(offset + len(l))
    return [Node(None, offset, offset + len(l))] + l + r

def make_random_tree(numbers):
  l = len(numbers)
  assert(l >= 1)
  if l == 1:
    return Node(numbers[0])
  p = random.randrange(1, l)
  return Node(None, make_random_tree(numbers[:p]), make_random_tree(numbers[p:]))

def make_challenge():
  count = random.randrange(3, 7)
  numbers = struct.unpack("Q"*count, os.urandom(count * 8))
  expected = struct.pack("QQQ", min(numbers), max(numbers), len(numbers))
  t1 = make_random_tree(numbers)
  count = random.randrange(3, 7)
  t2 = make_random_tree(struct.unpack("Q"*count, os.urandom(count * 8)))
  nodes = Node(None, t1, t2).serialize()
  shuffled_map = list(range(1, len(nodes)))
  random.shuffle(shuffled_map)
  reverse_map = [None] * len(nodes)
  for to, fr in enumerate(shuffled_map):
    reverse_map[fr] = to
  data = b""
  for idx in shuffled_map:
    node = nodes[idx]
    if node.value is None:
      data += struct.pack("QQ", reverse_map[node.left], reverse_map[node.right])
    else:
      data += struct.pack("QQ", (1 << 64) - 1, node.value)
  data = struct.pack("Q", reverse_map[nodes[0].left]) + data
  return expected, data

def check(expected, result):
  return expected == result
