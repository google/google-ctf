#!/usr/bin/env python3
# Copyright 2019 Google LLC
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


import asyncio
import base64
import struct

PATCHER = None

def untemper(x):
  x ^=  x >> 43;
  x ^= (x << 37) & 0xFFF7EEE000000000;
  x ^= (x << 17) & 0x00000003eda60000;
  x ^= (x << 17) & 0x00067ffc00000000;
  x ^= (x << 17) & 0x71d0000000000000;
  x ^= (x >> 29) & 0x0000000555555540;
  x ^= (x >> 29) & 0x0000000000000015;
  return x

assert(untemper(202) == 1193466305211289738)
assert(untemper(112) == 1188967069255749744)
assert(untemper(131) == 58549458119823811)


async def parse_point(reader):
  data = await reader.readline()
  return base64.b64decode(data.decode('utf-8').split()[1])

async def discard_line(reader):
  return  await reader.readline()
  print("Discarding {}", data)

async def send_bogus_point(writer):
  return writer.write(base64.b64encode(b"\x01"*32) + b"\n")

async def send_zero_point(writer):
  return writer.write(base64.b64encode(b"\x00"*32) + b"\n")

async def send_line(data, writer):
  return writer.write(base64.b64encode(data) + b"\n")

async def give_me_the_flag(x, writer, reader):
  writer.write(str(x).encode('utf-8') + b"\n")
  return (await reader.readline()).decode('utf-8').strip()

# Solution based on bit twiddling
async def solve(n, c1, writer, reader):
  nsq = n * n
  d = {0:c1}
  i, p, x = 0, 2, c1
  while p < n:
    i, p, x = i + 1, p * 2, (x * x) % nsq
    ans = await give_me_the_flag(x, writer, reader)
    if ans == TOO_HIGH: break
    elif ans == TOO_LOW: pass
    else:
      print(ans)
      return 0
    d[i] = x
  i = max(d.keys())
  x = d[i]
  i = i - 1
  while i >= 0:
    nx = (x * d[i]) % nsq
    ans = await give_me_the_flag(nx, writer, reader)
    if ans == TOO_LOW:
      print("Too low")
      x = nx
    elif ans == TOO_HIGH:
      print("Too high")
      pass
    else:
      print("good")
      return 0
    i -= 1
  return 1

def format_patch(ints):
  return struct.pack("<%dQ"%len(ints), *ints)

M = 156

async def async_main(address, port):
  reader, writer = await asyncio.open_connection(address, port)
  point = await parse_point(reader)
  print(point)
  await send_bogus_point(writer)
  await send_bogus_point(writer)
  ints = [0]*M + [untemper(x) for x in point]
  print(ints)
  await send_line(format_patch(ints), writer)
  await reader.readline()  # BOO, try again.
  print(await parse_point(reader))
  await send_zero_point(writer)
  await send_zero_point(writer)
  await send_line(b"Give me the flag, you bloody scoundrel!", writer)
  flag = await reader.readline()
  print(flag)

def main():
  loop = asyncio.get_event_loop()
  loop.run_until_complete(async_main('localhost', 1338))
  loop.close()

if __name__ == '__main__':
  main()
