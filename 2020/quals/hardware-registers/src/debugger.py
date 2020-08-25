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
import asyncio
import os
import sys
import time
import signal
import termios
import logging
import functools


## Modes of Operation
# Debugger session:
# &D

# Challenge mode:
# &C

# Terminate Session by the client:
# &T

## Messages
# Exception message passed to the client:
# !ERROR TEXT$

# Info message:
# #INFO TEXT$

## Application
# Write one input character:
# @WXX

## Debugger
# Single step:
# *S

# Run NUMBER steps:
# *S|NUMBER$

# Continue, will respond with registers information:
# *C

# Stop, will respond with registers information:
# *K

# Trace toggle:
# *T

# Breakpoint hit:
# *B|NNNN

# Breakpoint list request:
# *B?

# Breakpoint list answer:
# *B#$
# *B#-ADDR1$
# *B#+ADDR1-ADDR2$

# Set Breakpoint to ADDR:
# *B+ADDR

# Remove Breakpotint number NNNN:
# *B-NNNN

# Toggle Breakpotint number NNNN:
# *B!NNNN

# Display registers:
# *R?

# Registers info
# *I|CYCLES,PC,SP,FLAGS,R0,...,R31$

# Update registers (NN is a number: 00 ... 31):
# *R|NN=VVVV,NN=VVVV$


TARGET_IP = None
TARGET_PORT = 1337

g_last_cmd = 'step'
g_in_debug = False
g_challenge = True
g_cycle = 0
g_last_cycle = 0
g_update_cycle = 0


def parse_number(v):
  if v[0] == '*':
    v = v[1:]
  if v[0] == '$':
    return int(v[1:], 16)
  elif v[:2] == '0x':
    return int(v, 16)
  return int(v)


def ctrl_c_handler(loop, writer):
  global g_in_debug
  global g_challenge
  global g_update_cycle

  if g_in_debug:
    return

  if g_challenge:
    writer.write(b'&T')
    return

  g_in_debug = True
  if g_update_cycle == -1:
    g_update_cycle = -2
  writer.write(b'*K')
  fd = sys.stdin.fileno()
  loop.remove_reader(fd)
  loop.add_signal_handler(signal.SIGINT, functools.partial(ctrl_c_handler, loop, writer))
  loop.add_reader(fd, functools.partial(cmd_handler, loop, writer))
  sys.stdout.write('\nDBG> ')
  sys.stdout.flush()


def stdio_input(loop, writer):
  fd = sys.stdin.fileno()
  old_cfg = termios.tcgetattr(fd)
  try:
    new_cfg = termios.tcgetattr(fd)
    new_cfg[3] = new_cfg[3] & ~(termios.ECHO | termios.ICANON)
    new_cfg[6][termios.VMIN] = 1
    new_cfg[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSADRAIN, new_cfg)
    word = os.read(fd, 1)
    writer.write(bytes('@W%02X' % ord(word), 'utf-8'))
  finally:
    termios.tcsetattr(fd, termios.TCSADRAIN, old_cfg)


def set_stdio_input(loop, writer):
  global g_in_debug

  g_in_debug = False
  fd = sys.stdin.fileno()
  loop.remove_reader(fd)
  loop.add_reader(fd, functools.partial(stdio_input, loop, writer))


def set_cmd_handler(loop, writer):
  global g_in_debug
  global g_challenge

  if g_in_debug or g_challenge:
    return

  sys.stdout.write('DBG> ')
  sys.stdout.flush()
  g_in_debug = True
  loop.add_reader(sys.stdin.fileno(), functools.partial(cmd_handler, loop, writer))


async def target_handler(loop, reader, writer):
  global g_challenge
  global g_cycle
  global g_last_cycle
  global g_update_cycle

  cmd_buf = ''
  while True:
    data = str(await reader.read(4096), 'utf-8')
    if data == '':
      writer.close()
      break

    cmd_buf += data
    while len(cmd_buf) >= 2:
      cls = cmd_buf[0]
      if cls == '&' and cmd_buf[1] == 'M':
        cmd_buf = cmd_buf[2:]
        while True:
          try:
            sys.stdout.write('Please choose mode of operation:\n D - debug session\n C - challenge mode\nChoice: ')
            choice = sys.stdin.readline().strip()
            if choice in ['d', 'D', 'C', 'c']:
              writer.write(bytes('&%c' % choice, 'utf-8'))
              await writer.drain()
              loop.add_signal_handler(signal.SIGINT, functools.partial(ctrl_c_handler, loop, writer))
              if choice in ['d', 'D']:
                g_challenge = False
                set_cmd_handler(loop, writer)
              else:
                set_stdio_input(loop, writer)
              break
          except KeyboardInterrupt:
            print('\nQuitting...')
            writer.write(b'&T')
            await writer.drain()
            break

      elif cls == '!' or cls == '#':
        try:
           end = cmd_buf.index('$')
           msg = cmd_buf[1:end]
           if cls == '!':
             logging.error('Exception: {}'.format(msg))
             break
           else:
             logging.info('{}'.format(msg))
           cmd_buf = cmd_buf[end+1:]
        except ValueError:
           # Need more data
           break

      elif cls == '@':
        if len(cmd_buf) < 4:
          # Need more data
          break

        if cmd_buf[1] == 'W':
          ch = int(cmd_buf[2:4], 16)
          cmd_buf = cmd_buf[4:]
          sys.stdout.write('%c' % ch)
          sys.stdout.flush()
        else:
          logging.error('Unknown application command: {}'.format(cmd_buf[1]))
          return

      elif cls == '*':
        if len(cmd_buf) < 3:
          break
        if cmd_buf[1] == 'I' and cmd_buf[2] == '|':
          try:
            end = cmd_buf.index('$')
          except:
            # Need more data
            break
          regs = cmd_buf[3:end].split(',')
          cycle, pc, sp, flg = regs[0:4]
          if g_update_cycle == 1:
            g_update_cycle = -1
            g_last_cycle = int(cycle)
            cmd_buf = cmd_buf[end+1:]
            continue
          else:
            g_cycle = int(cycle)
            if g_update_cycle == -2:
              g_update_cycle = 0
              sys.stdout.write('\nCycles passed: %d\nDBG> ' % (g_cycle - g_last_cycle))
              cmd_buf = cmd_buf[end+1:]
              continue

          def r_fmt(n, regs):
            s = ''
            for i in range(len(regs)):
              k = n + i
              if k == 32:
                s += '%sgp%d = %06X  ' % (' ' if k < 10 else '', k, int(regs[i], 16))
              else:
                s += '%sgp%d = %02X  ' % (' ' if k < 10 else '', k, int(regs[i], 16))
            return s[:-2]

          regs1 = regs[4:12]
          regs2 = regs[12:20]
          regs3 = regs[20:28]
          regs4 = regs[28:]
          print('\n pc = %06X %s' % (int(pc, 16), r_fmt(0, regs1)))
          print(' sp = %04X   %s' % (int(sp, 16), r_fmt(len(regs1), regs2)))
          print('flg = %02X     %s' % (int(flg, 16), r_fmt(len(regs1)+len(regs2), regs3)))
          print('%012X %s' % (int(cycle), r_fmt(len(regs1)+len(regs2)+len(regs3), regs4)))
          cmd_buf = cmd_buf[end+1:]

        elif cmd_buf[1] == 'B':
          if len(cmd_buf) < 4:
            # Need more data
            break
          if cmd_buf[2] == '|':
            if len(cmd_buf) < 7:
              # Need more data
              break
            bpn = int(cmd_buf[3:7])
            if not bpn:
              logging.error('Wrong breakpoint hit data')
              return
            cmd_buf = cmd_buf[7:]
            print('\nBreakpoint hit #%d' % bpn)
            if g_update_cycle == -1:
              g_update_cycle = 0
              print('Cycles passed: %d' % (g_cycle - g_last_cycle))

            set_cmd_handler(loop, writer)
          elif cmd_buf[2] == '#':
            try:
              end = cmd_buf.index('$')
            except ValueError:
              continue

            bps = cmd_buf[3:end]
            bn = 1
            for bp in [(bps[i:i+5]) for i in range(0, len(bps), 5)]:
              print('%02d: PC = $%06x%s' % (bn, int(bp[1:], 16), '' if bp[0] == '+' else ' (disabled)'))
              bn += 1

            cmd_buf = cmd_buf[end+1:]
          else:
            logging.error('Unknown Breakpoint command: {}'.format(cmd_buf[2]))
            return

        else:
          logging.error('Unknown debug command: {}'.format(cmd_buf[1]))
          return

      else:
          logging.error('Unknown command: {}'.format(cls))
          return


def cmd_handler(loop, writer):
  global g_in_debug
  global g_last_cmd
  global g_update_cycle

  line = sys.stdin.readline().strip()
  cmds = line.split(';')
  do_sleep = 0
  has_continue = False
  for cmd_in in cmds:
    cmd_in = cmd_in.strip()
    if cmd_in == '':
      cmd_in = g_last_cmd

    args = cmd_in.split(' ')
    cmd = args[0]
    args = args[1:]

    cmdw = ''
    if cmd in ['s', 'step']:
      if args:
        cmdw = '*S|%d$' % parse_number(args[0])
        g_update_cycle = 1
      else:
        cmdw = '*S'

    elif cmd in ['c', 'cont']:
      cmd_in = 'reg'
      cmdw = '*C'
      has_continue = True
      g_update_cycle = 1
      set_stdio_input(loop, writer)

    elif cmd in ['p', 'pause']:
      if args:
        do_sleep = float(args[0])

    elif cmd in ['i', 'input']:
      if args:
        cmdw = ''.join(['@W%02X' % ord(c) for c in cmd_in[len(cmd)+1:]])
      cmdw += '@W0A'

    elif cmd in ['t', 'trace']:
      cmdw = '*T'

    elif cmd in ['r', 'reg']:
      if args and (len(args) % 2) == 0:
        def pairwise(i):
          a = iter(i)
          return zip(a, a)

        cmdw = '*R|'
        for n, v in pairwise(args):
          cmdw += '%02d=%04X,' % (parse_number(n), parse_number(v))
        cmdw = cmdw[:-1] + '$'
      else:
        cmdw = '*R?'

    elif cmd in ['b', 'break']:
      if len(args) == 1:
        cmdw = '*B+%04X' % parse_number(args[0])
      elif len(args) == 0:
        cmdw = '*B?'
      elif args[0] in ['d', 'delete']:
        cmdw = '*B-%04d' % parse_number(args[1])
      elif args[0] in ['t', 'toggle']:
        cmdw = '*B!%04d' % parse_number(args[1])
    elif cmd in ['q', 'quit', 'exit']:
      cmdw = '&T'

    elif cmd in ['w', 'write']:
      if len(args) == 1:
        cmdw = args[0]

    elif cmd in ['h', '?', 'help']:
      print('Available commands:\n  step [COUNT]\n  input STR\n  cont\n  trace\n  pause SECS\n  reg [<RN> <VALUE>] ... [<RN> <VALUE>]\n  break [delete|toggle N] | [ADDR]\n  write RAW-COMMAND\n  quit|exit\n')

    else:
      print('Unknown command: {}'.format(cmd_in))

    if cmdw:
      g_last_cmd = cmd_in
      writer.write(bytes(cmdw, 'utf-8'))

    if do_sleep:
      time.sleep(do_sleep)
      do_sleep = 0

  if not has_continue:
    sys.stdout.write('DBG> ')
    sys.stdout.flush()


@asyncio.coroutine
def main_task(loop):
  global g_in_debug
  global TARGET_IP
  global TARGET_PORT

  if not TARGET_IP and len(sys.argv) < 2:
    print('No TARGET_IP has been specified!')
    sys.exit(1)
  if len(sys.argv) >= 3:
    TARGET_PORT = int(sys.argv[2])
  if len(sys.argv) >= 2:
    TARGET_IP = sys.argv[1]

  try:
    reader, writer = yield from asyncio.open_connection(TARGET_IP, TARGET_PORT)
  except KeyboardInterrupt:
    print("Quiting...")
    sys.exit(0)

  yield from target_handler(loop, reader, writer)

  writer.close()
  yield from writer.wait_closed()


def main():
  logging.basicConfig(level=logging.INFO)

  loop = asyncio.get_event_loop()
  try:
    loop.run_until_complete(main_task(loop))
  finally:
    loop.close()


if __name__ == '__main__':
  main()
