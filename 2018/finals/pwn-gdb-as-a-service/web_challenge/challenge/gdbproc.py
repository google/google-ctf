#!/usr/bin/env python3
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import struct
import os
import threading
import re
import functools
import codecs
import psutil
import asyncio
import asyncio.subprocess

def re_findall(q, s):
  idx = 0
  while True:
    match = re.search(q, s[idx:])
    if not match:
      break
    yield idx+match.start()
    idx += match.start()+1

def string_findall(q, s):
  idx = 0
  while True:
    idx = s.find(q, idx)
    if idx < 0:
      break
    yield idx
    idx = idx+1

class GDBInterrupt(object):
  def __init__(self):
    pass

class GDBCommand(object):
  def __init__(self, data, reply_queue = None):
    self.data = data
    self._reply_queue = reply_queue
  def will_continue(self):
    return self._reply_queue == None
  async def reply(self, pkt):
    if self._reply_queue:
      await self._reply_queue.put(pkt)

class GDBError(object):
  def __init__(self, msg):
    self.msg = msg

class GDBReply(object):
  def __init__(self, data):
    self.data = data
  def is_stop_reply(self):
    return self.data.startswith(b'T')

class ExitMsg(object):
  def __init__(self):
    pass

def gdb_checksum(cmd):
  checksum = functools.reduce(lambda csum, c: (csum+c)%256, cmd, 0)
  return '{:02x}'.format(checksum).encode('ascii')

def gdb_encode(s):
  out = b''
  for c in s:
    if c in b'#$}':
      out += b'}'+bytes([c ^ 0x20])
    else:
      out += bytes([c])
  return out

def gdb_decode(s):
  out = b''
  i = 0
  while i < len(s):
    c = s[i]
    if c == ord('*'):
      cnt = s[i+1] - 29
      out += bytes([out[-1]]*cnt)
      i += 2
    elif c == ord('}'):
      c = s[i+1]
      c = bytes([c ^ 0x20])
      out += c
      i += 2
    else:
      out += bytes([c])
      i += 1
  return out

def gdb_format_cmd(s):
  return b'$' + s + b'#' + gdb_checksum(s)

def gdb_make_pkt(data):
  return gdb_format_cmd(gdb_encode(data))

async def message_broker(pkt_queue, reply_queue, stop_reply_queue, gdbserver_stdin):
  stopped = True
  while True:
    pkt = await pkt_queue.get()
    if isinstance(pkt, GDBCommand):
      if not stopped:
        await pkt.reply(GDBError('not stopped'))
        continue
      gdbserver_stdin.write(gdb_make_pkt(pkt.data))
      if pkt.will_continue():
        stopped = False
        continue
      reply = await reply_queue.get()
      await pkt.reply(reply)
    elif isinstance(pkt, GDBInterrupt):
      if stopped:
        continue
      gdbserver_stdin.write(b'\x03')
    elif isinstance(pkt, ExitMsg):
      return
    else:
      assert isinstance(pkt, GDBReply)
      assert pkt.is_stop_reply()
      assert not stopped
      stopped = True
      await stop_reply_queue.put(pkt)

async def packet_reader(pkt_queue, reply_queue, gdbserver_stdout):
  while True:
    next_char = await gdbserver_stdout.read(1)
    if not next_char:
      return
    if next_char == b'+':
      # ignore acks
      continue
    if next_char != b'$':
      raise Exception('unexpected character (want $, got {!r})'.format(next_char))
    pkt = b''
    pkt += (await gdbserver_stdout.readuntil(b'#'))[:-1]
    checksum = await gdbserver_stdout.read(2)
    if not checksum == gdb_checksum(pkt):
      raise Exception('wrong checksum {} vs {}, "{}"'.format(checksum, gdb_checksum(pkt), pkt))
    reply = GDBReply(gdb_decode(pkt))
    if reply.is_stop_reply():
      await pkt_queue.put(reply)
    else:
      await reply_queue.put(reply)

class GDBProcess(object):
  @staticmethod
  async def create(argv, stop_reply_queue, env={}, log_fn=None):
    self = GDBProcess()
    self._bp_mutex = threading.Lock()
    self._breakpoints = {}
    self._log_fn = log_fn
    self._p = await asyncio.create_subprocess_exec('gdbserver', '--once', '-', *argv, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, preexec_fn=os.setsid, env=env, close_fds=True, bufsize=0)
    self._pkt_queue = asyncio.Queue()
    reply_queue = asyncio.Queue()
    loop = asyncio.get_event_loop()
    self._msg_broker = loop.create_task(message_broker(self._pkt_queue, reply_queue, stop_reply_queue, self._p.stdin))
    self._pkt_reader = loop.create_task(packet_reader(self._pkt_queue, reply_queue, self._p.stdout))
    self._proc_dir_fd = None
    await self._start_no_ack()
    return self

  def breakpoints(self):
    return list(self._breakpoints.keys())

  def _log(self, msg):
    if self._log_fn:
      self._log_fn(msg)

  async def release(self):
    self._log('killing gdb process')
    self._msg_broker.cancel()
    self._pkt_reader.cancel()
    os.killpg(os.getpgid(self._p.pid), 9)
    await self._p.wait()
    self._log('killed gdb process')

  def open_proc_file(self, filename, mode='r'):
    if not self._proc_dir_fd:
      child_processes = psutil.Process(self._p.pid).children()
      assert len(child_processes) == 1
      child_pid = child_processes[0].pid
      self._proc_dir_fd = os.open('/proc/{}/'.format(child_pid), os.O_PATH)
    return open('/proc/self/fd/{}/{}'.format(self._proc_dir_fd, filename), mode)

  def maps(self):
    mappings = []
    with self.open_proc_file('maps', 'r') as fd:
      for line in fd.read().splitlines():
        start,end,perm,name = re.match('^([0-9a-f]+)-([0-9a-f]+)\s+([rwx-]{3})p\s+[0-9a-f]+\s+[0-9a-f]{2}:[0-9a-f]{2}\s+[0-9a-f]+\s+(.*)$', line).groups()
        start = int(start, 16)
        end = int(end, 16)
        size = end - start
        mappings.append((start, size, perm, name))
    return mappings

  def search(self, q, qtype, max_match_count = 64):
    mappings = self.maps()
    matches = []
    with self.open_proc_file('mem', 'rb') as mem_fd:
      for start, size, perm, _ in mappings:
        try:
          mem_fd.seek(start)
        except ValueError:
          continue
        except OverflowError:
          self._log('overflow error')
          continue
        try:
          data = mem_fd.read(size)
        except IOError:
          continue
        try:
          if qtype == 'regex':
            search_fn = re_findall
          else:
            search_fn = string_findall
            if qtype != 'string':
              if qtype == 'char':
                format_char = 'B'
              elif qtype == 'short':
                format_char = 'H'
              elif qtype == 'int':
                format_char = 'I'
              else:
                # long
                format_char = 'Q'
              q = struct.pack(format_char, int(q, 0))
          for idx in search_fn(q, data):
            match = data[idx:idx+max(32, len(q))]
            matches.append([start+idx, match])
            if len(matches) > max_match_count:
              break
        except ValueError:
          continue
    return matches

  async def _write_pkt(self, cmd):
    self._log('_write_pkt("{}")'.format(cmd))
    reply_queue = asyncio.Queue(maxsize=1)
    await self._pkt_queue.put(GDBCommand(cmd, reply_queue))
    pkt = await reply_queue.get()
    if isinstance(pkt, GDBError):
      raise Exception(pkt.msg)

    assert isinstance(pkt, GDBReply)
    return pkt.data

  async def _start_no_ack(self):
    resp = await self._write_pkt(b'QStartNoAckMode')
    if resp != b'OK':
      raise Exception('NoAck response: "{}"'.format(resp))
    self._p.stdin.write(b'+')

  async def set_breakpoint(self, addr):
    with self._bp_mutex:
      if addr in self._breakpoints:
        return
      self._log('setting breakpoint at 0x{:x}'.format(addr))
      hardware_breakpoint = len(self._breakpoints) < 4
      command = 'Z1' if hardware_breakpoint else 'Z0'
      resp = await self._write_pkt('{},{:x},1'.format(command, addr).encode('ascii'))
      if resp != b'OK':
        raise Exception('Breakpoint error: "{}"'.format(resp))
      self._breakpoints[addr] = hardware_breakpoint

  async def remove_breakpoint(self, addr):
    with self._bp_mutex:
      hardware_breakpoint = self._breakpoints[addr]
      command = 'z1' if hardware_breakpoint else 'z0'
      resp = await self._write_pkt('{},{:x},1'.format(command, addr).encode('ascii'))
      if resp != b'OK':
        raise Exception('Breakpoint error: "{}"'.format(resp))
      del self._breakpoints[addr]

  def _cont(self, mode):
    self._pkt_queue.put_nowait(GDBCommand(b'vCont;'+mode))

  def cont(self):
    self._cont(b'c')

  def step(self):
    self._cont(b's')

  def interrupt(self):
    self._log('interrupting with 0x03')
    self._pkt_queue.put_nowait(GDBInterrupt())

  _REG_NAMES = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "eflags", "cs", "ss", "ds", "es", "fs", "gs"]

  async def get_reg(self, name):
    return (await self.get_regs())[name]

  async def get_regs(self):
    resp = await self._write_pkt(b'g')
    data = codecs.decode(resp, 'hex_codec')
    regs = {}
    for i in range(len(GDBProcess._REG_NAMES)):
      regs[GDBProcess._REG_NAMES[i]] = struct.unpack('Q', data[i*8:(i+1)*8])[0]
    return regs

  def read_mem(self, addr, count):
    data = b''
    with self.open_proc_file('mem', 'rb') as mem_fd:
      try:
        mem_fd.seek(addr)
        data = mem_fd.read(count)
      except:
        try:
          mem_fd.seek(addr)
          for i in range(count):
            data += mem_fd.read(1)
        except:
          pass
    return data

async def main():
  def log(msg):
    print('[*] {}'.format(msg))

  stop_queue = asyncio.Queue()

  import time

  print('creating process')
  p = await GDBProcess.create(['/bin/sleep', '5'], stop_queue, log_fn=log)
  print('process created')

  await p.set_breakpoint(0x7ffff7dda886)
  print('breakpoint at 0x7ffff7dda886')

  p.cont()
  await stop_queue.get()
  for i in range(10):
    p.step()
    await stop_queue.get()
    print(hex((await p.get_regs())['rip']))

  p.cont()
  await asyncio.sleep(0.1)
  p.interrupt()
  await stop_queue.get()
  print(hex((await p.get_regs())['rip']))
  await p.release()

if __name__ == "__main__":
  loop = asyncio.get_event_loop()
  loop.run_until_complete(main())
  loop.close()
