#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

VERSION = 's'
MODULUS = 2**1279-1
CHALSIZE = 2**128

SOLVER_URL = 'https://github.com/google/google-ctf/blob/master/infrastructure/kctf/base/nsjail-docker/proof_of_work/pow.py'

def stdin_is_localhost_socket():
    try:
        sock = socket.socket(fileno=sys.stdin.fileno())
        peername = sock.getpeername()
        sock.detach()
        return peername[0] == '::ffff:127.0.0.1'
    except OSError:
        return False

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

def verify_challenge(chal, sol):
    [diff, x] = decode_challenge(chal)
    [y] = decode_challenge(sol)
    res = sloth_square(y, diff, MODULUS)
    return (x == res) or (MODULUS - x == res)

def usage():
    sys.stdout.write('Usage:\n')
    sys.stdout.write('Solve pow: {} solve $challenge\n')
    sys.stdout.write('Check pow: {} ask $difficulty\n')
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
            sys.exit(0)

        if stdin_is_localhost_socket():
            sys.exit(0)

        challenge = get_challenge(difficulty)

        sys.stdout.write("== proof-of-work ==\n")
        sys.stdout.write("please solve a pow first\n")
        sys.stdout.write("You can find the solver at:\n")
        sys.stdout.write("  {}\n".format(SOLVER_URL))
        sys.stdout.write("./pow.py solve {}\n".format(challenge))
        sys.stdout.write("===================\n")
        sys.stdout.write("\n")
        sys.stdout.write("Solution? ")
        sys.stdout.flush()
        solution = ''
        while not solution:
            solution = sys.stdin.readline().strip()

        if verify_challenge(challenge, solution):
            sys.stdout.write("Correct")
            sys.stdout.flush()
            sys.exit(0)
        else:
            sys.stdout.write("Proof-of-work fail")
            sys.stdout.flush()

    elif cmd == 'solve':
        challenge = sys.argv[2]
        solution = solve_challenge(challenge)

        if verify_challenge(challenge, solution):
            sys.stdout.write("Solution: \n{}\n".format(solution))
            sys.stdout.flush()
            sys.exit(0)
    else:
        usage()

    sys.exit(1)

if __name__ == "__main__":
    main()
