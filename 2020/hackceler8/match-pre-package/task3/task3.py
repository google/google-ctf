#!/usr/bin/python3
import sys
import os
import hashlib
import py_compile

def flag_checker(candidate):
  random = b"aes-128-ecb"
  key = hashlib.sha512(random).digest()
  correct = bytearray([242, 122, 104, 129, 95, 139, 6, 78, 89, 144, 165, 79, 212, 62, 71, 57, 211, 116, 128])
  candidate = bytearray(bytes(candidate, "utf-8"))
  for i in range(min(len(candidate), len(key))):
    candidate[i] ^= key[i]

  if correct == candidate:
    print("Yes, that's the flag")
  else:
    print("Not sure that's that. Not a flag though.")

print("vvvv Here's some binary data. Figure it out.")
print("")
print("")
sys.stdout.flush()

py_compile.compile(__file__, cfile="/tmp/out.pyc")

with open("/tmp/out.pyc", "rb") as f:
  sys.stdout.buffer.write(f.read())
  sys.stdout.buffer.flush()

print("")
print("")
print("^^^^ Here's some binary data. Figure it out.")
sys.stdout.flush()

