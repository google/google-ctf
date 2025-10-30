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

import pwn
import pwnlib.tubes

FLAG = "CTF{st3ph3n_str4ng3_0nly_us3s_m1ps_wh4t_a_n00b}"

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

def chal1_solve() -> int:
    a = (0x1337 << 16) | 1337
    b = a ^ 0x8675309

    return 0xaaaaaaaa - b

def chal2_solve() -> bytes:
    val = ((0x7331 << 32) // 0xcafebabe) + 7

    return pwn.p32(val)


def chal3_solve_cached() -> int:
    """Fast return to avoid making the test take a long time."""

    return 2629548852

chal1_ans = chal1_solve()
pwn.log.info(f"chal1 answer: {chal1_ans}")
r.sendline(str(chal1_ans).encode())

chal2_ans = chal2_solve()
pwn.log.info(f"chal2 answer: {chal2_ans}")
r.sendline(chal2_ans)

chal3_ans = chal3_solve_cached()
pwn.log.info(f"chal3 answer: {chal3_ans}")
r.sendline(str(chal3_ans).encode())

output = r.recvall(timeout=3).decode()
assert FLAG in output, f"test failed, output:\n{output}"
pwn.log.success("chal solved successfully")

exit(0)