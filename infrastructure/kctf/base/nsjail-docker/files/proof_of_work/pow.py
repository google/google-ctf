#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hmac
import secrets
import sys
import socket

SOLVER_URL = 'https://github.com/google/google-ctf/blob/master/infrastructure/kctf/base/nsjail-docker/proof_of_work/pow.py'

def stdin_is_localhost_socket():
    try:
        sock = socket.socket(fileno=sys.stdin.fileno())
    except OSError:
        return False

    peername = sock.getpeername()
    sock.detach()

    return peername[0] == '::ffff:127.0.0.1'

def gen_seed():
    return secrets.token_hex(8)

def byte_has_leading_zeroes(b, count):
    if count == 0:
        return True

    for i in range(count):
        if (b & 1) == 1:
            return False
        b >>= 1

    return True

def has_leading_zeroes(inp, count):
    for b in inp:
        if count > 8:
            if b != 0:
                return False
            count -= 8
            continue

        return byte_has_leading_zeroes(b, count)

    if count == 0:
        return True

    raise Exception('input too short for requested leading zeroes')

def check_pow(seed, solution, difficulty):
    digest = hmac.digest(seed, solution, 'sha256')
    return has_leading_zeroes(digest, difficulty)

def usage():
    sys.stdout.write('Usage:\n')
    sys.stdout.write('Solve pow: {} solve seed difficulty\n')
    sys.stdout.write('Check pow: {} ask difficulty\n')
    sys.stdout.flush()
    sys.exit(1)

def find_pow_solution(seed, difficulty):
    for i in range((1<<64)-1):
        solution = i.to_bytes(8, 'little')
        if check_pow(seed, solution, difficulty):
            sys.stdout.write("Solution: {}\n".format(solution.hex()))
            sys.stdout.flush()
            return True

    return False

def main():
    if len(sys.argv) < 2:
        usage()

    cmd = sys.argv[1]

    if cmd == 'ask':
        if len(sys.argv) != 3:
            usage()
        seed_hex = gen_seed()
        difficulty = int(sys.argv[2])
        if difficulty == 0:
            sys.exit(0)

        if stdin_is_localhost_socket():
            sys.exit(0)

        sys.stdout.write("== proof-of-work ==\n")
        sys.stdout.write("please solve a pow first\n")
        sys.stdout.write("You can find the solver at:\n")
        sys.stdout.write("  {}\n".format(SOLVER_URL))
        sys.stdout.write("./pow.py solve {} {}\n".format(seed_hex, difficulty))
        sys.stdout.write("===================\n")
        sys.stdout.write("\n")
        sys.stdout.write("Solution? ")
        sys.stdout.flush()
        solution = bytes.fromhex(sys.stdin.readline())
        seed = bytes.fromhex(seed_hex)

        if check_pow(seed, solution, difficulty):
            sys.stdout.write("Proof-of-work fail")
            sys.stdout.flush()
            sys.exit(0)
        else:
            sys.exit(1)

    elif cmd == 'solve':
        if len(sys.argv) != 4:
            usage()

        seed = bytes.fromhex(sys.argv[2])
        difficulty = int(sys.argv[3])

        if find_pow_solution(seed, difficulty):
            sys.exit(0)
        else:
            sys.exit(1)

    else:
        usage()

if __name__ == "__main__":
    main()
