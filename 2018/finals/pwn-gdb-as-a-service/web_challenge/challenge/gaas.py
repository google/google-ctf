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

from aiohttp import web
import capstone
import functools
from gdbproc import GDBProcess
import socketio
import asyncio
import codecs
import os

enable_logging = False

premium = 'PREMIUM' in os.environ
if premium:
  access_key = os.getenv('PREMIUM_KEY')
  runnable = ['/home/user/printwebflag']
else:
  access_key = os.getenv('TRIAL_KEY')
  runnable = ['/bin/sleep', '20']

MAX_INSN_LEN = 15

capstone_md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

sio = socketio.AsyncServer()
app = web.Application()
sio.attach(app)

with open('index.html') as f:
  index_html = f.read()

async def index(request):
  if not 'key' in request.cookies:
    return web.Response(status=401, text='permission denied (missing key)', content_type='text/html')
  if request.cookies['key'] != access_key:
    return web.Response(status=401, text='permission denied (invalid key)', content_type='text/html')
  return web.Response(text=index_html, content_type='text/html')

app.add_routes([web.get('/', index),
                web.get('/{name}', index)])

gdb_sessions = {}
stop_queue_readers = {}

async def on_shutdown(app):
  await asyncio.gather(delete_gdb_process(sid) for sid in gdb_sessions.keys())

app.on_shutdown.append(on_shutdown)

def log(msg):
  if enable_logging:
    print('[*] {}'.format(msg))

@sio.on('connect')
def connect(sid, environ):
  log('connected {}'.format(sid))
  if not 'key={}'.format(access_key) in environ['HTTP_COOKIE']:
    log('access_key not found {}'.format(environ['HTTP_COOKIE']))
    return False

@sio.on('disconnect')
async def disconnect(sid):
  log('disconnected {}'.format(sid))
  await delete_gdb_process(sid)

async def stop_queue_reader(sid, queue):
  while True:
    pkt = await queue.get()
    await update_all(sid)

async def create_gdb_process(sid):
  stop_queue = asyncio.Queue()
  gdb_sessions[sid] = await GDBProcess.create(runnable, stop_queue, env={'KEY': access_key}, log_fn=log)
  loop = asyncio.get_event_loop()
  stop_queue_readers[sid] = loop.create_task(stop_queue_reader(sid, stop_queue))

async def delete_gdb_process(sid):
  if sid in gdb_sessions:
    stop_queue_readers[sid].cancel()
    del stop_queue_readers[sid]
    await gdb_sessions[sid].release()
    del gdb_sessions[sid]

@sio.on('start')
async def start(sid):
  await delete_gdb_process(sid)
  await create_gdb_process(sid)
  # Reading registers doesn't work on ubuntu 18.04 for some reason.
  # Step once as a work around
  step(sid)

async def update_all(sid):
  log('updating sid {}'.format(sid))
  regs_task = getregs(sid)
  maps_task = getmaps(sid)
  asm_task = getasm(sid, {'addr': await gdb_sessions[sid].get_reg('rip'), 'count': 100})
  await asyncio.gather(regs_task, maps_task, asm_task)
  log('update done')

@sio.on('step')
def step(sid):
  gdb_sessions[sid].step()

@sio.on('cont')
def cont(sid):
  gdb_sessions[sid].cont()

@sio.on('stop')
def stop(sid):
  gdb_sessions[sid].interrupt()

async def getregs(sid):
  regs = await gdb_sessions[sid].get_regs()
  await sio.emit('regs', regs, room=sid)

@sio.on('mem')
async def getmem(sid, msg):
  addr = msg['addr']
  count = msg['count']
  data = gdb_sessions[sid].read_mem(addr, count)
  await sio.emit('mem', {'addr': addr, 'data': data}, room=sid)

async def getmaps(sid):
  maps = gdb_sessions[sid].maps()
  await sio.emit('maps', maps, room=sid)

@sio.on('break')
async def setbreakpoint(sid, data):
  addr = data['addr']
  await gdb_sessions[sid].set_breakpoint(addr)
  await sio.emit('breakpoints', gdb_sessions[sid].breakpoints(), room=sid)

@sio.on('unbreak')
async def rmbreakpoint(sid, data):
  addr = data['addr']
  await gdb_sessions[sid].remove_breakpoint(addr)
  await sio.emit('breakpoints', gdb_sessions[sid].breakpoints(), room=sid)

@sio.on('search')
async def search(sid, data):
  q = data['q']
  qtype = data['type']
  await sio.emit('search_result', gdb_sessions[sid].search(q.encode(), qtype), room=sid)

async def getasm(sid, data):
  addr = data['addr']
  count = data['count']
  result = []
  for _ in range(count):
    data = gdb_sessions[sid].read_mem(addr, MAX_INSN_LEN)
    try:
      disasm = next(capstone_md.disasm_lite(data, addr))
    except StopIteration:
      break
    result.append(disasm)
    addr += disasm[1]
  await sio.emit('asm', result, room=sid)

if __name__ == '__main__':
  web.run_app(app)
