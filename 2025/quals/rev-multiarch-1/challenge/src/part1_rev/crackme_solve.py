#!/usr/bin/env python3
# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import ctypes

from pwn import *

FLAG = "flag{nice_work}"
p = process(["../../rev-multiarch-1/challenge/multiarch", "crackme.bin"], env={"FLAG": FLAG})
if "debug" in sys.argv:
    context.terminal = ["tmux", "splitw", "-v"]
    gdb.attach(p, "\n".join([
        # GDB commands here
        "b execute_regvm_insn",
    ]))


def chal1_solve() -> int:
    a = (0x1337 << 16) | 1337
    b = a ^ 0x8675309

    return 0xaaaaaaaa - b

def chal2_solve() -> bytes:
    val = ((0x7331 << 32) // 0xcafebabe) + 7

    return p32(val)

def chal3_solve() -> int:
    """Logic for how this can be solved for real. Usually finds a seed in <15sec."""

    libc = ctypes.CDLL("libc.so.6")

    with log.progress("finding rand seed") as p:
        while True:
            seed = random.randint(0, 0xffffffff)
            libc.srand(seed)

            for _ in range(10):
                val = libc.rand() & 0xffff
                val |= (libc.rand() & 0xffff) << 16

                val ^= 0x133700
                val ^= 0xf2f2f2f2
                val &= 0xffffff

                if val == 0xc0ffee:
                    p.success(f"found a seed! {seed}")
                    return seed

def chal3_solve_cached() -> int:
    """Fast return to avoid making the test take a long time."""

    return 2629548852

chal1_ans = chal1_solve()
log.info(f"chal1 answer: {chal1_ans}")
p.sendline(str(chal1_ans).encode())

chal2_ans = chal2_solve()
log.info(f"chal2 answer: {chal2_ans}")
p.sendline(chal2_ans)

# chal3_ans = chal3_solve()
chal3_ans = chal3_solve_cached()
log.info(f"chal3 answer: {chal3_ans}")
p.sendline(str(chal3_ans).encode())

output = p.recvall(timeout=3).decode()
assert FLAG in output, f"test failed, output:\n{output}"
log.success("chal solved successfully")
