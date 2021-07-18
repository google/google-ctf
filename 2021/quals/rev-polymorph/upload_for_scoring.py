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

import base64
import secrets
import socket
import sys
import hashlib
import subprocess
import time

VERSION = 's'
MODULUS = 2**1279-1
CHALSIZE = 2**128

SOLVER_URL = 'https://goo.gle/kctf-pow'

def sloth_root(x, diff, p):
    for i in range(diff):
        x = pow(x, (p + 1) // 4, p) ^ 1
    return x

def sloth_square(y, diff, p):
    for i in range(diff):
        y = pow(y ^ 1, 2, p)
    return y

def encode_number(num):
    size = (num.bit_length() // 24) * 3 + 3
    return str(base64.b64encode(num.to_bytes(size, 'big')), 'utf-8')

def decode_number(enc):
    return int.from_bytes(base64.b64decode(bytes(enc, 'utf-8')), 'big')

def decode_challenge(enc):
    dec = enc.split('.')
    if dec[0] != VERSION:
        raise Exception('Unknown challenge version')
    return list(map(decode_number, dec[1:]))

def encode_challenge(arr):
    return '.'.join([VERSION] + list(map(encode_number, arr)))

def get_challenge(diff):
    x = secrets.randbelow(CHALSIZE)
    return encode_challenge([diff, x])

def solve_challenge(chal):
    [diff, x] = decode_challenge(chal)
    y = sloth_root(x, diff, MODULUS)
    return encode_challenge([y])

def can_bypass(chal, sol):
    from ecdsa import VerifyingKey
    from ecdsa.util import sigdecode_der
    if not sol.startswith('b.'):
        return False
    sig = bytes.fromhex(sol[2:])
    with open("/kctf/pow-bypass/pow-bypass-key-pub.pem", "r") as fd:
        vk = VerifyingKey.from_pem(fd.read())
    return vk.verify(signature=sig, data=bytes(chal, 'ascii'), hashfunc=hashlib.sha256, sigdecode=sigdecode_der)

def verify_challenge(chal, sol, allow_bypass=True):
    if allow_bypass and can_bypass(chal, sol):
        return True
    [diff, x] = decode_challenge(chal)
    [y] = decode_challenge(sol)
    res = sloth_square(y, diff, MODULUS)
    return (x == res) or (MODULUS - x == res)

def usage():
    sys.stdout.write('Usage:\n')
    sys.stdout.write('Solve pow: {} solve $challenge\n')
    sys.stdout.write('Check pow: {} ask $difficulty\n')
    sys.stdout.write('  $difficulty examples (for 1.6GHz CPU):')
    sys.stdout.write('             1337: 10 secs')
    sys.stdout.write('             31337: 5 mins')
    sys.stdout.flush()
    sys.exit(1)

def main():
    if len(sys.argv) != 3:
        usage()
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'ask':
        difficulty = int(sys.argv[2])

        if difficulty == 0:
            sys.stdout.write("== proof-of-work: disabled ==\n")
            sys.exit(0)


        challenge = get_challenge(difficulty)

        sys.stdout.write("== proof-of-work: enabled ==\n")
        sys.stdout.write("please solve a pow first\n")
        sys.stdout.write("You can run the solver with:\n")
        sys.stdout.write("    python3 <(curl -sSL {}) solve {}\n".format(SOLVER_URL, challenge))
        sys.stdout.write("===================\n")
        sys.stdout.write("\n")
        sys.stdout.write("Solution? ")
        sys.stdout.flush()
        solution = ''
        while not solution:
            solution = sys.stdin.readline().strip()

        if verify_challenge(challenge, solution):
            sys.stdout.write("Correct\n")
            sys.stdout.flush()
            sys.exit(0)
        else:
            sys.stdout.write("Proof-of-work fail")
            sys.stdout.flush()

    elif cmd == 'solve':
        challenge = sys.argv[2]
        solution = solve_challenge(challenge)

        if verify_challenge(challenge, solution, False):
            sys.stderr.write("Solution: \n".format(solution))
            sys.stderr.flush()
            sys.stdout.write(solution)
            sys.stdout.flush()
            sys.stderr.write("\n")
            sys.stderr.flush()
            sys.exit(0)
    else:
        usage()

    sys.exit(1)


if len(sys.argv) != 4:
  cname = sys.argv[0]
  sys.stderr.write(f"Usage: {cname} <binary_to_upload> <host> <port>\n")
  sys.exit(1)

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((sys.argv[2], int(sys.argv[3])))

recvbuf = b""
while not recvbuf.endswith(b"== proof-of-work: "):
  recvbuf += sock.recv(1)

enablement = sock.recv(7)
recvbuf = b""
if enablement == b"enabled":
  while not recvbuf.endswith(b"kctf-pow) solve "):
    recvbuf += sock.recv(1)

  challenge = b""
  while not challenge.endswith(b"\n"):
    challenge += sock.recv(1)

  sys.stderr.write("Solving proof-of-work %s\n" % challenge)
  solution = solve_challenge(challenge.decode("utf-8"))
  
  sock.sendall(solution.encode("utf-8") + b"\n")
  sys.stderr.write("Proof-of-work solved.\n")

with open(sys.argv[1], "rb") as f:
  data = f.read()
  sz = len(data).to_bytes(4, "little")
  for c in sz:
    sys.stderr.write(f"{c} ")
  sys.stderr.write(f"\n")
  sys.stderr.write(f"Sending all data\n")
  sock.sendall(sz)
  sock.sendall(data)

while True:
  sys.stdout.buffer.write(sock.recv(1))
  sys.stdout.flush()


