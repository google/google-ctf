#!/usr/bin/python3
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

