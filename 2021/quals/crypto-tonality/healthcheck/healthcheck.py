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
import hashlib
import struct
import sys

# http://www.secg.org/SEC2-Ver-1.0.pdf
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

def handle_pow(tube):
    print(tube.recvuntil(b'python3 '))
    print(tube.recvuntil(b' solve '))
    challenge = tube.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    tube.sendline(solution)
    print(tube.recvuntil(b'Correct\n'))

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

def hash_message(msg):
  h = hashlib.sha1()
  h.update(msg)
  return h.digest()

def truncated_hash(n:int, digest: bytes) -> int:
  h = int.from_bytes(digest, 'big')
  truncate_bits = len(digest) * 8 - n.bit_length()
  if truncate_bits > 0:
    h >>= truncate_bits
  return h

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--port', metavar='P', type=int, default=1337, help='challenge #port')
  args = parser.parse_args()

  tube = pwnlib.tubes.remote.remote('127.0.0.1', args.port)
  print(tube.recvuntil('== proof-of-work: '))
  if tube.recvline().startswith(b'enabled'):
      handle_pow(tube)

  # Implements related key attack against ECDSA.
  # See section 4.2 in https://eprint.iacr.org/2015/1135
  # "On the Security of the Schnorr Signature Scheme and DSA against Related-Key Attacks"
  # Hiraku Morita and Jacob C.N. Schuldt and Takahiro Matsuda and Goichiro Hanaoka and Tetsu Iwata
  hello = read_message(tube, challenge_pb2.HelloResponse)
  n = P256_N
  z0 = truncated_hash(n, hash_message(hello.message0.encode()))
  z1 = truncated_hash(n, hash_message(hello.message1.encode()))

  # a <- z0 / z1 mod N
  a = z0 * pow(z1, -1, n)
  a %= n

  # Query signing oracle.
  sign_req = challenge_pb2.SignRequest()
  sign_req.scalar = a.to_bytes((a.bit_length() + 7) // 8, 'big')
  write_message(tube, sign_req)

  sign_res = read_message(tube, challenge_pb2.SignResponse)
  r = int.from_bytes(sign_res.message0_sig.r, 'big')
  s = int.from_bytes(sign_res.message0_sig.s, 'big')

  # s <- s / a mod N
  s = s * pow(a, -1, n)
  s %= n

  # Send forged signature for m1.
  verify_req = challenge_pb2.VerifyRequest()
  verify_req.message1_sig.r = r.to_bytes((r.bit_length() + 7) // 8, 'big')
  verify_req.message1_sig.s = s.to_bytes((s.bit_length() + 7) // 8, 'big')
  write_message(tube, verify_req)

  verify_res = read_message(tube, challenge_pb2.VerifyResponse)
  print(verify_res)
  assert(verify_res.flag.startswith('CTF{'))
  assert(verify_res.flag.endswith('}'))
  return 0


if __name__ == '__main__':
  sys.exit(main())
