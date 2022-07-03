#!/usr/bin/env python3
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

import z3
import os
import math

flag1 = "CTF{H0p3_y0u_l1k"
flag2 = "3_3LF_m4g1c}"

def rc4_prng(key, count, modified=False):
    if isinstance(key, str):
        key = [ord(c) for c in key]

    S = []
    for i in range(256):
        S.append(i)

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]

    i = 0
    j = 0
    keystream = []
    for _ in range(count):
        if not modified:
            i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
        if modified:
            i = (i + 1) % 256
    return keystream

def rc4_encrypt(input):
    inputz = input + "\0"
    enc = []
    for i in range(0, len(input), 2):
        enc += rc4_prng(inputz[i:i+2], 3, True)
    return enc

def rc4_decrypt(encoded):
    vals = dict()
    for b0 in range(33, 127):
        for b1 in range(33, 127):
            enc = rc4_prng([b0, b1], 3, True)
            val = 0
            for b in enc:
                val = val * 256 + b
            if val in vals:
                vals[val] = "CONFLICT"
                print("rc4_decrypt: decryption conflict was found: '%c%c' with '%c%c' -> %s == %d" % (
                    b0, b1, vals[val][0], vals[val][1], enc, val))
            vals[val] = [b0, b1]

    decoded = ""
    for i in range(0, len(encoded), 3):
        enc = encoded[i:i+3]
        val = 0
        for b in enc:
            val = val * 256 + b
        dec = vals[val]
        if dec == "CONFLICT":
            raise Exception("rc4_decrypt: this input cannot be used as it would cause a conflict during decryption!")
        decoded += chr(dec[0]) + chr(dec[1])
    return decoded

def eq_checker(input, seed = 'test_seed', only_multi = True, factor = 1):
    l = len(input)
    l2 = math.ceil(l * factor)

    rnds = rc4_prng(seed, l2*l)

    # 0..9 - multi_in_reloc
    # 10 - mul, 11 - xor, 12 - or, 13 - and, 14 - rol,
    # 15 - ror, 16 - add, 17 - sub, 18 - shl, 19 - shr
    if only_multi:
        ops = [0] * (l2*l)
    else:
        ops = rc4_prng(seed + '_ops', l2*l)

    ops = [x % 20 for x in ops]
    for i in range(len(ops)):
        if ops[i] in [16,17]:
            ops[i] = 0
        if ops[i] >= 18:
            rnds[i] %= 7

    rnds = [rnds[i*l : (i+1)*l] for i in range(l2)]
    ops = [ops[i*l : (i+1)*l] for i in range(l2)]

    solver = z3.Solver()
    if only_multi:
        vars = [z3.Int('f%d' % i) for i in range(l)]
    else:
        vars = [z3.BitVec('f%d' % i, 20) for i in range(l)]

    def ROR(x, y):
        y %= 8
        return ((x >> y) | (x << (8 - y))) & 0xff

    def ROL(x, y):
        y %= 8
        return ((x << y) | (x >> (8 - y))) & 0xff

    z3_sum = 0
    sums = []
    for i in range(l2):
        sum = 0
        desc = []
        z3eq = 0
        for j in range(l):
            rnd = rnds[i][j]
            # 0..9 - multi_in_reloc
            # 10 - mul, 11 - xor, 12 - or, 13 - and, 14 - rol,
            # 15 - ror, 16 - add, 17 - sub, 18 - shl, 19 - shr
            op  = ops[i][j]
            if op == 11: # XOR
                sum  += input[j] ^ rnd
                z3eq += vars[j] ^ rnd
                desc.append("(f%d ^ %d)" % (j, rnd))
            elif op == 12: # OR
                sum  += input[j] | rnd
                z3eq += vars[j] | rnd
                desc.append("(f%d | %d)" % (j, rnd))
            elif op == 13: # AND
                sum  += input[j] & rnd
                z3eq += vars[j] & rnd
                desc.append("(f%d & %d)" % (j, rnd))
            elif op == 14: # TODO: ROL
                sum  += ROL(input[j], rnd)
                z3eq += ROL(vars[j], rnd)
                desc.append("rol(f%d, %d)" % (j, rnd))
            elif op == 15: # TODO: ROR
                sum  += ROR(input[j], rnd)
                z3eq += ROR(vars[j], rnd)
                desc.append("ror(f%d, %d)" % (j, rnd))
            elif op == 16: # ADD
                sum  += (input[j] + rnd) & 0xff
                z3eq += (vars[j] + rnd) & 0xff
                desc.append("(f%d + %d)" % (j, rnd))
            elif op == 17: # SUB
                sum  += (input[j] - rnd) & 0xff
                z3eq += (vars[j] - rnd) & 0xff
                desc.append("(f%d - %d)" % (j, rnd))
            elif op == 18: # SHL
                sum  += (input[j] << rnd) & 0xff
                z3eq += (vars[j] << rnd) & 0xff
                desc.append("(f%d << %d)" % (j, rnd))
            elif op == 19: # SHR
                sum  += (input[j] >> rnd) & 0xff
                z3eq += (vars[j] >> rnd) & 0xff
                desc.append("(f%d >> %d)" % (j, rnd))
            else: # MUL
                sum  += rnd * input[j]
                z3eq += rnd * vars[j]
                desc.append("%d*f%d" % (rnd, j))

        print("eq[%d]: %s == %d" % (i, ' + '.join(desc), sum))
        if i < l2-0:
            z3_sum += z3eq - sum
            solver.add(z3eq == sum)
            sums.append(sum)

    return (rnds, ops, sums, solver, vars)

def solve_and_check(name, solver, vars, expected, minChar = 0, maxChar = 255):
    for var in vars:
        solver.add(minChar <= var)
        solver.add(var <= maxChar)

    print("z3: sat/unsat? %s" % solver.check())

    m = solver.model()
    #print("z3: %s: %s" % (name, ("%s" % m).replace('\n', '')))

    solved = [int(str(m[v])) for v in vars]
    print("z3: %s = %s" % (name, solved))
    print("z3: %s = %s" % (name, ' '.join('%02x' % x for x in solved)))
    print("z3: %s = %s" % (name, ''.join(chr(x) for x in solved)))

    if solved != expected:
        raise Exception("%s: z3 solution is not correct (expected=%s, got=%s)" % (name, expected, solved))
    else:
        print("z3 solution of %s is CORRECT!" % name)

print("Encrypting first of the flag...")
enc_flag1 = rc4_encrypt(flag1)
print("enc_flag1 = %s (len=%d)" % (' '.join("%02x"%x for x in enc_flag1), len(enc_flag1)))
print()

print("Test decryption...")
dec_flag1 = rc4_decrypt(enc_flag1)
if dec_flag1 != flag1:
    raise Exception("rc4_decrypt is not correct (expected='%s', got='%s')" % (flag1, dec_flag1))
print()

print("Generating system of equations for the first part of the flag...")
(flag1_rnds, flag1_ops, flag1_sums, flag1_solver, flag1_vars) = eq_checker(enc_flag1, 'flag1', True)
print()

print("Solving the equations...")
solve_and_check('enc_flag1', flag1_solver, flag1_vars, enc_flag1)
print()

print("Generating system of equations for the second part of the flag...")
flag2v = [ord(c) for c in flag2]
(flag2_rnds, flag2_ops, flag2_sums, flag2_solver, flag2_vars) = eq_checker(flag2v, 'flag2', False, 1.4)
print()

print("Solving the equations...")
flag2_solver.add(flag2_vars[-1] == ord('}'))
solve_and_check('flag2', flag2_solver, flag2_vars, flag2v, 33, 126)
print()

print("Saving results...")
with open('flag_data.py', 'wt') as f:
    f.write('flag1 = {"rnds": %s, "ops": %s, "sums": %s, "value": "%s"}\n' % (flag1_rnds, flag1_ops, flag1_sums, flag1))
    f.write('flag2 = {"rnds": %s, "ops": %s, "sums": %s, "value": "%s"}\n' % (flag2_rnds, flag2_ops, flag2_sums, flag2))
print()

print("Total eq count: %d + %d = %d" % (len(flag1_sums), len(flag2_sums), len(flag1_sums) + len(flag2_sums)))
