# Copyright 2022 Google LLC
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

import sys
import random
import time

def ks(seed):
  random.seed(seed)
  while True:
    yield (random.randint(0, 255) * 13 + 17) % 256

# Xor s with a keystream.
def cry(s, seed):
  r = []
  for x, y in zip(ks(seed), s):
    r.append(x ^ y)

  return bytes(r)

def fail(s):
  print(s)
  print("Thanks for playing!")
  sys.exit(0)

def game1():
  def w(m, i, j):
    return (m >> (i*10 + j)) & 1

  print()
  print("Get to work!")
  m = 1267034045110727999721745963007
  fuel = 8
  x, y = 1, 1
  stops = set([(5, 4), (3, 3)])
  log = ""
  while True:
    print("Fuel:", fuel)
    for i in range(10):
      s = ""
      for j in range(10):
        if w(m, i, j):
          s += "🧱"
        elif (j, i) == (x, y):
          s += "🚓"
        elif (j, i) == (8, 8):
          s += "🏁"
        elif (j, i) in stops:
          s += "⛽️"
        else:
          s += "  "
      print(s)
    inp = input().strip()
    for c in inp:
      log += c
      if c not in "wasd":
        fail("Nope!")
      if fuel == 0:
        fail("Empty...")
      dx, dy = {"w": (0, -1), "s": (0, 1), "a": (-1, 0), "d": (1, 0)}[c]
      x += dx
      y += dy
      if w(m, y, x):
        fail("Crash!")
      fuel -= 1
      if (x, y) in stops:
        stops.remove((x, y))
        fuel += 15
      if (x, y) == (8, 8):
        print("Nice!")
        return log

def game2():
  print()
  print("Math quiz time!")
  qs = [
      ("sum", 12, 5),
      ("difference", 45, 14),
      ("product", 8, 9),
      ("ratio", 18, 6),
      ("remainder from division", 23, 7)
    ]
  log = "_"
  for q in qs:
    print("What is the %s of %d and %d?" % q)
    x, a, b = q
    if x == "sum": r = a + b
    elif x == "difference": r = a - b
    elif x == "product": r = a * b
    elif x == "ratio": r = a // b
    elif x == "remainder from division": r = a % b
    else:
      fail("What?")
    inp = int(input())
    if inp == r:
      print("Correct!")
      log += str(inp) + "_"
    else:
      fail("Wrong!")
  return log

def game3():
  print()
  print("Speed typing game.")
  t = time.time()
  text = """
  Text: Because of its performance advantage, today many language implementations
  execute a program in two phases, first compiling the source code into bytecode,
  and then passing the bytecode to the virtual machine.
  """
  words = text.split()
  it = 1
  log = "_"
  while it != len(words):
    print("%0.2f seconds left." % (20 - (time.time() - t)))
    print("\033[32m%s\033[39m %s" % (" ".join(words[:it]), words[it]))
    inp = input()
    if time.time() > t + 20:
      fail("Too slow!")
    if inp == words[it]:
      log += words[it].upper() + "_"
      it += 1
    else:
      fail("You made a mistake!")
  print("Nice!")
  return log



def main():
  print("Pass 3 tests to prove your worth!")
  seed = "seed:"
  # Maze
  seed += game1() + ":"
  # Quiz
  seed += game2() + ":"
  # Speed typing
  seed += game3()
  print()
  print("You can drive to work, know some maths and can type fast. You're hired!")
  print("Your sign-on bonus:", cry(b'\xa0?n\xa5\x7f)\x1f6Jvh\x95\xcc!\x1e\x95\x996a\x11\xf6OV\x88\xc1\x9f\xde\xb50\x9d\xae\x14\xde\x18YHI\xd8\xd5\x90\x8a\x181l\xb0\x16^O;]', seed).decode())
