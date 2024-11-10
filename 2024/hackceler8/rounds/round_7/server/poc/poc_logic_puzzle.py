# Copyright 2024 Google LLC
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

# Semi-manual PoC that solves the example puzzle.
# To use it on a random-generated puzzle:
# * Query the chest statements
# * Rewrite constraints with the appropriate new constraint based on the statements
# * Run this PoC to get the list of mimics
# * Open all chests that aren't mimics and talk to the NPC to get the stars.


from z3 import *

# Map layout:
#
#   1 2 3 4
# a x x x x
# b x x x .
# c . x . x
# d . x . .

# Rewrite this part with statements from server
# (e.g. a1 says "There are 3 mimics in this row!" -> "a1: 3 row")
constraints = """
a1: 3 row
a2: 0 adj
a3: 2 adj
a4: 3 row
b1: 3 col
b2: 3 col
b4: 3 row
c2: 1 col
c4: 3 col
d2: 0 col
""".strip()

def choose(arr, count):
  return PbEq([(x,1) for x in arr], len(arr) - count)

def statement(stater, st):
  return Or(And(stater, st), And(Not(stater), Not(st)))

a1 = Bool('a1')
a2 = Bool('a2')
a3 = Bool('a3')
a4 = Bool('a4')
b1 = Bool('b1')
b2 = Bool('b2')
b3 = Bool('b3')
b4 = Bool('b4')
c1 = Bool('c1')
c2 = Bool('c2')
c3 = Bool('c3')
c4 = Bool('c4')
d1 = Bool('d1')
d2 = Bool('d2')
d3 = Bool('d3')
d4 = Bool('d4')
vs = [a1, a2, a3, a4, b1, b2, b3, b4, c1, c2, c3, c4, d1, d2, d3, d4]
matrix = [[a1, a2, a3, a4], [b1, b2, b3, b4], [c1, c2, c3, c4], [d1, d2, d3, d4]]

s = Solver()

# 6 to 10 mimics
s.add(Or(PbEq([(x,1) for x in vs], 16 - 6),
         PbEq([(x,1) for x in vs], 16 - 7),
         PbEq([(x,1) for x in vs], 16 - 8),
         PbEq([(x,1) for x in vs], 16 - 9),
         PbEq([(x,1) for x in vs], 16 - 10)))

for c in constraints.split("\n"):
  pos, statem = c.split(": ")
  num, layout = statem.split(" ")
  num = int(num)
  x = int(pos[1])-1
  y = ord(pos[0])-ord('a')
  if layout == "row":
    s.add(statement(matrix[y][x], choose([matrix[y][i] for i in range(4)], num)))
  elif layout == "col":
    s.add(statement(matrix[y][x], choose([matrix[i][x] for i in range(4)], num)))
  elif layout == "adj":
    adjs = []
    for offs in [(0, 1), (1, 0), (0, -1), (-1, 0)]:
      xx, yy = offs
      xx += x
      yy += y
      if xx >= 0 and xx < 4 and yy >= 0 and yy < 4:
        adjs.append(matrix[yy][xx])
    s.add(statement(matrix[y][x], choose(adjs, num)))
  # print(c, ":", x, y, num, layout)

print(s.check())
m = s.model()
print(m)
print()
for row in range(0, 4):
  r = ""
  for col in range(0, 4):
    r += "-" if m[matrix[row][col]] else " " if m[matrix[row][col]] is None else "M"
  print(r)
