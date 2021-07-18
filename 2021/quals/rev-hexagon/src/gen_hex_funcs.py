#!/usr/bin/env python3
#
# Copyright (C) 2020 Google LLC
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import sys
import random
from io import StringIO


class SelectNode(object):

  def __init__(self):
    self.bit = random.randint(0, 8)

  def ToAsm(self, label):
    return '''
  {{ p0 = tstbit(r1, #{0})
     if (p0.new) jump:t {1} }}
'''.format(self.bit, label)


class ModifierNode(object):

  def ToAsm(self):
    raise NotImplemented()


class XorModifierNode(ModifierNode):

  def __init__(self):
    self.oper = random.randint(0, 0xffffffff)

  def ToAsm(self):
    return '''
  {{ r5 = #{0} }}
  {{ r0 = xor(r0, r5) }}
'''.format(self.oper)


class AddModifierNode(ModifierNode):

  def __init__(self):
    self.oper = random.randint(0, 0xffffffff)

  def ToAsm(self):
    return '''
  {{ r5 = #{0} }}
  {{ r0 = add(r0, r5) }}
'''.format(self.oper)


class NotModifierNode(ModifierNode):

  def __init__(self):
    pass

  def ToAsm(self):
    return '''
  {{ r0 = not(r0) }}
'''.format()


def NewModifierNode():
  return random.choice([
      lambda: XorModifierNode(),
      lambda: AddModifierNode(),
      lambda: NotModifierNode(),
  ])()


class Hexagon(object):

  def __init__(self, name):
    self.name = name
    self.top = SelectNode()
    self.right1 = NewModifierNode()
    self.right2 = NewModifierNode()
    self.left1 = NewModifierNode()
    self.left2 = NewModifierNode()

  def ToAsm(self):
    return '''
.globl {0}
{0}:
{1}

{2}
  {{ jump 1f }}

1:
{3}
  {{ jump 4f }}

2:
{4}
  {{ jump 3f }}

3:
{5}
  {{ jump 4f }}

4:
  {{ jumpr lr }}
'''.format(self.name, self.top.ToAsm('2f'), self.right1.ToAsm(),
           self.right2.ToAsm(), self.left1.ToAsm(), self.left2.ToAsm())


def BuildHexFunctions(num):
  hexes = []
  for i in range(num):
    hexes.append(Hexagon('hex%d' % (i + 1)))
  return hexes


def ProduceAsm(f, hexes):
  for h in hexes:
    f.write(h.ToAsm())


def main():
  f = StringIO()
  f.write('''
.text
''')

  random.seed(0)
  ProduceAsm(f, BuildHexFunctions(6))

  realf = open(sys.argv[1], 'w')
  realf.write(f.getvalue())
  realf.close()
  f.close()


if __name__ == '__main__':
  main()
