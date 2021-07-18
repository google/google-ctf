#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2021 Google LLC
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

import argparse
import pwnlib
import challenge_pb2
import struct
import sys

def handle_pow(tube):
  raise NotImplemented()

def read_message(tube, typ):
  n = struct.unpack('<L', tube.recvnb(4))[0]
  buf = tube.recvnb(n)
  msg = typ()
  msg.ParseFromString(buf)
  return msg

def write_message(tube, msg):
  buf = msg.SerializeToString()
  tube.send(struct.pack('<L', len(buf)))
  tube.send(buf)

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--port', metavar='P', type=int, default=1337, help='challenge #port')
  parser.add_argument(
      '--host', metavar='H', type=str, default='tonality.2021.ctfcompetition.com', help='challenge host')
  args = parser.parse_args()

  tube = pwnlib.tubes.remote.remote(args.host, args.port)
  print(tube.recvuntil('== proof-of-work: '))
  if tube.recvline().startswith(b'enabled'):
      handle_pow(tube)

  # Step 1: Hello.
  hello = read_message(tube, challenge_pb2.HelloResponse)
  print(hello)

  # Step 2: Sign.
  a = 1234
  sign_req = challenge_pb2.SignRequest()
  sign_req.scalar = a.to_bytes((a.bit_length() + 7) // 8, 'big')
  write_message(tube, sign_req)

  sign_res = read_message(tube, challenge_pb2.SignResponse)
  print(sign_res)

  # Step 3: Verify.
  verify_req = challenge_pb2.VerifyRequest()
  verify_req.message1_sig.r = b'\x11\x22'
  verify_req.message1_sig.s = b'\x33\x44'
  write_message(tube, verify_req)

  verify_res = read_message(tube, challenge_pb2.VerifyResponse)
  print(verify_res)
  return 0


if __name__ == '__main__':
  sys.exit(main())
