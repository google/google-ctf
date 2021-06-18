#!/usr/bin/python3
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
import sys
import os
import random
import time

FLAG = os.environ["TASK1_FLAG"]

OFFSET = random.randint(38, 42)

def get_correct():
  return int(time.time()) + OFFSET

print("Download path <game server>/0c16c4dd438b0042c4d725fab588e648.py\n")
print("Oh! Look what time it is: " + str(int(time.time())))
print("Yes! It's guessing o'clock!")

while True:
  try:
    s = input("Now, tell me the number I'm thinking about: ")
    v = int(s.strip())

    if v != get_correct():
      print("Hahaha. No.")
      continue

    print(FLAG)
    break

  except ValueError:
    print("That's not a number, go away.")
    break
  except EOFError:
    print("Ohes Noes!")
    break

