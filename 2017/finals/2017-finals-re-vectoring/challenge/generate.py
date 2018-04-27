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

from fixpoint import fixpoint, Buf
from pwn import *

intrs = ['READ_BYTE',
         'WRITE_BYTE',
         'CPUID',
         'GET_PC',
         'ADD',
         'SUBL',
         'SUBR',
         'MUL',
         'AND',
         'OR',
         'XOR',
         'NOT',
         'GET',
         'PUT',
         'GET_MEM',
         'PUT_MEM',
         'CONST',
         'JMP',
         'JNZ']
instrs = {k: n for n, k in enumerate(intrs)}

def instr(i, reg = 0, arg = None):
    if isinstance(reg, str):
        assert reg[0] == 'r' and len(reg) == 2
        reg = int(reg[1])
    assert 0 <= reg <= 3
    i = instrs[i]
    if isinstance(arg, (int, long)):
        arg = p64(arg)
    else:
        arg = ''
    return p8(4 * i + reg) + arg

def iread_byte():
    return instr('READ_BYTE')
def iwrite_byte():
    return instr('WRITE_BYTE')
def icpuid():
    return instr('CPUID')
def iget_pc():
    return instr('GET_PC')
def iadd(reg):
    return instr('ADD', reg)
def isubl(reg):
    return instr('SUBL', reg)
def isubr(reg):
    return instr('SUBR', reg)
def imul(reg):
    return instr('MUL', reg)
def iand(reg):
    return instr('AND', reg)
def ior(reg):
    return instr('OR', reg)
def ixor(reg):
    return instr('XOR', reg)
def inot():
    return instr('NOT')
def iget(reg):
    return instr('GET', reg)
def iput(reg):
    return instr('PUT', reg)
def iget_mem(reg):
    return instr('GET_MEM', reg)
def iput_mem(reg):
    return instr('PUT_MEM', reg)
def iconst(n):
    return instr('CONST', arg = n)
def ijnz(reg):
    return instr('JNZ', reg)
def ijmp():
    return instr('JMP')

def get(src):
    if isinstance(src, (int, long)):
        return iconst(src)
    elif src == 'pc':
        return iget_pc()
    elif src == 'cpuid':
        return icpuid()
    elif src == 'stdin':
        return iread_byte()
    elif src[0] == '*':
        return iget_mem(src[1:])
    elif src[0] == 'r':
        return iget(src)
    else:
        return iconst(safeeval.expr(src))

def put(dst):
    if dst == 'stdout':
        return iwrite_byte()
    elif dst[0] == '*':
        return iput_mem(dst[1:])
    else:
        return iput(dst)

funs = {
    'nop': lambda: '\x90',
    'mov': lambda dst, src: get(src) + put(dst),
    'not': lambda dst: get(dst) + inot() + put(dst),
    'jmp': lambda dst: get(dst) + ijmp(),
    'jnz': lambda dst, src: get(dst) + ijnz(src),
}

op2s = {
    'add': (iadd, iadd),
    'mul': (imul, imul),
    'and': (iand, iand),
    'or':  (ior, ior),
    'xor': (ixor, ixor),
    'sub': (isubl, isubr),
}
def op2(name, dst, src):
    f, g = op2s[name]
    if src[0] == 'r':
        return get(dst) + f(src) + put(dst)
    else:
        return get(src) + g(dst) + put(dst)
for k in op2s.keys():
    funs[k] = (lambda name: lambda dst, src: op2(name, dst, src))(k)

def asm(s):
    out = []

    for line in s.split('\n'):
        line = line.split('#', 1)[0].strip().lower()
        if not line:
            continue
        parsed = line.split(None, 1)
        op, args = parsed[0], (parsed + [''])[1]
        args = tuple(a.strip() for a in args.split(','))
        if len(args) == 1 and not args[0]:
            args = []

        try:
            out.append(funs[op](*args))
        except Exception as e:
            raise Exception('bad: ' + line, e)
    return ''.join(out)

@fixpoint
def code(m):
    call_number = [0]
    def call(buf):
        label = m['call_label_%d' % call_number[0]]
        call_number[0] += 1
        return [
            asm('mov r3, %d' % label),
            asm('jmp %d' % buf),
            label
        ]

    return [
        asm('mov r0, cpuid'),
        asm('mul r0, 8'),
        asm('add r0, %d' % m.reset_vec),
        asm('mov r0, *r0'),
        asm('jmp r0'),

        m.read_byte,
        asm('mov r1, cpuid'),
        asm('mul r1, 16'),
        asm('add r1, %d' % m.stdin_area),
        asm('mov *r1, 1'),
        m.read_byte_wait_loop,
        asm('mov r0, *r1'),
        asm('jnz %d, r0' % m.read_byte_wait_loop),
        asm('add r1, 8'),
        asm('mov r0, *r1'),
        asm('jmp r3'),

        m.gobble_newline,
        asm('mov r1, cpuid'),
        asm('mul r1, 8'),
        asm('add r1, %d' % m.gobble_save_area.ptr),
        asm('mov *r1, r3'),
        m.gobble_loop,
        asm('and r0, 0xff'),
        asm('sub r0, 0xa'),
        asm('not r0'),
        asm('jnz %d, r0' % m.gobble_after.ptr),
        call(m.read_byte),
        asm('jmp %d' % m.gobble_loop),
        m.gobble_after,
        asm('mov r1, cpuid'),
        asm('mul r1, 8'),
        asm('add r1, %d' % m.gobble_save_area.ptr),
        asm('jmp *r1'),
        m.gobble_save_area(p64(0) * 4),

        m.write_byte,
        asm('mov r1, cpuid'),
        asm('mul r1, 16'),
        asm('add r1, %d + 8' % m.stdout_area),
        asm('mov *r1, r0'),
        asm('sub r1, 8'),
        asm('mov *r1, 1'),
        m.write_byte_wait_loop,
        asm('mov r0, *r1'),
        asm('jnz %d, r0' % m.write_byte_wait_loop),
        asm('jmp r3'),

        m.write_string,
        asm('mov r1, cpuid'),
        asm('mul r1, 16'),
        asm('add r1, %d' % m.write_string_save_area),
        asm('mov *r1, r2'),
        asm('add r1, 8'),
        asm('mov *r1, r3'),
        asm('mov r2, r0'),
        m.write_string_loop,
        asm('mov r0, *r2'),
        asm('add r2, 1'),
        asm('and r0, 0xff'),
        asm('mov r3, %d' % m.write_string_loop),
        asm('jnz %d, r0' % m.write_byte),
        asm('mov r1, cpuid'),
        asm('mul r1, 16'),
        asm('add r1, %d' % m.write_string_save_area),
        asm('mov r2, *r1'),
        asm('add r1, 8'),
        asm('jmp *r1'),
        m.write_string_save_area(p64(0) * 2 * 4),

        m.thread1,
        asm('mov r0, %d' % m.thread1_wait),
        asm('mov r0, *r0'),
        asm('not r0'),
        asm('jnz %d, r0' % m.thread1),
        asm('mov r0, %d' % m.thread1_string),
        call(m.write_string),
        asm('jmp %d' % m.thread1_loop1),
        m.thread1_loop,
        call(m.gobble_newline),
        m.thread1_loop1,
        asm('mov r0, %d' % m.thread1_prompt),
        call(m.write_string),
        call(m.read_byte),
        asm('mov r1, r0'),
        asm('sub r1, %d' % ord('g')),
        asm('jnz %d, r1' % m.thread1_is_not_g),
        m.thread1_is_g,
        call(m.read_byte),
        asm('add r0, %d' % m.thread1_table),
        asm('mov r0, *r0'),
        asm('and r0, 0xff'),
        call(m.write_byte),
        asm('mov r0, 0xa'),
        call(m.write_byte),
        asm('jmp %d' % m.thread1_loop),
        m.thread1_is_not_g,
        asm('mov r1, r0'),
        asm('sub r1, %d' % ord('s')),
        asm('jnz %d, r1' % m.thread1_loop),
        m.thread1_is_s,
        call(m.read_byte),
        asm('mov r2, r0'),
        call(m.read_byte),
        asm('add r2, %d' % m.thread1_table),
        asm('mov r1, *r2'),
        asm('and r1, %d' % 0xffffffffffffff00),
        asm('add r1, r0'),
        asm('mov *r2, r1'),
        asm('mov r0, 1'),
        asm('jmp %d' % m.thread1_loop),

        m.thread1_wait(p64(0)),
        m.thread1_string("The protocol allows two commands, get and set.\n" +
                         "To get, send the byte 'g' along with a key.\n" +
                         "To set, send the byte 's' along with a key and a value\n\x00"),
        m.thread1_prompt("Command: \x00"),
        m.thread1_table(p8(0) * 128),

        # Places before the rest of thread0 to allow an overwrite
        m.thread0_password_ok,
        asm('mov r0, %d' % m.thread0_string_password_ok),
        call(m.write_string),
        asm('mov r0, %d' % m.thread1_wait),
        asm('mov *r0, 1'),
        asm('mov r0, %d' % m.thread0_infloop),
        m.thread0_infloop,
        asm('jmp r0'),

        m.thread0,
        asm('mov r0, %d' % m.thread0_string1),
        call(m.write_string),
        m.thread0_print_password,
        asm('mov r0, %d' % m.thread0_string2),
        call(m.write_string),
        asm('mov r2, %d' % m.thread0_password),
        m.thread0_read_loop,
        asm('mov r0, *r2'),
        asm('and r0, 0xff'),
        asm('not r0'),
        asm('jnz %d, r0' % m.thread0_password_ok),
        call(m.read_byte),
        asm('mov r1, r0'),
        asm('add r1, *r2'),
        asm('and r1, 0xff'),
        asm('jnz %d, r1' % m.thread0_gobble_newline),
        asm('add r2, 1'),
        asm('jmp %d' % m.thread0_read_loop),
        m.thread0_gobble_newline,
        call(m.gobble_newline),
        asm('jmp %d' % m.thread0_print_password),
        m.thread0_string1("Welcome to the key-value store\n\n\x00"),
        m.thread0_string2("Password: \x00"),
        m.thread0_string_password_ok("Correct!\n\n\x00"),
        m.thread0_password(unordlist(256 - ord(c) for c in "5acb8c765bba5c28\n") + '\x00'),

        m.stdout_thread,
        asm('add r0, 1'),
        asm('and r0, 3'),
        asm('mov r1, r0'),
        asm('mul r1, 16'),
        asm('add r1, %d' % m.stdout_area),
        asm('mov r2, *r1'),
        asm('not r2'),
        asm('jnz %d, r2' % m.stdout_thread),
        asm('add r1, 8'),
        asm('mov stdout, *r1'),
        asm('sub r1, 8'),
        asm('mov *r1, 0'),
        asm('jmp %d' % m.stdout_thread),
        m.stdout_area(p64(0) * 2 * 4),

        m.stdin_thread,
        asm('add r0, 1'),
        asm('and r0, 3'),
        asm('mov r1, r0'),
        asm('mul r1, 16'),
        asm('add r1, %d' % m.stdin_area),
        asm('mov r2, *r1'),
        asm('not r2'),
        asm('jnz %d, r2' % m.stdin_thread),
        asm('mov r2, stdin'),
        asm('add r1, 8'),
        asm('mov *r1, r2'),
        asm('sub r1, 8'),
        asm('mov *r1, 0'),
        asm('jmp %d' % m.stdin_thread),
        m.stdin_area(p64(0) * 2 * 4),

        m.reset_vec(m.thread0.ptr, m.thread1.ptr, m.stdout_thread.ptr, m.stdin_thread.ptr),
    ]

write('vm-code.bin', code)
