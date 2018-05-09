#!/usr/bin/python
# -*- coding: utf-8 -*-
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

context.arch = 'arm'
# context.randomize = True

#==============================================================================
#                                INITIALIZATION
#==============================================================================
anti_debug_setup = [
    # Set up our XOR key
'''
    eor r11, r11
'''
]

#==============================================================================
#                    BLOCK OFF SIGNALS SIGSEGV AND SIGTRAP
#==============================================================================
# This allows us to generate spurious SIGSEGV and SIGTRAP and continue
# execution as if nothing had gone wrong.
#
# For the SIGSEGV situation, we can do fun things like jumping to an un-mapped
# page, and the signal handler will keep incrementing $PC slowly until a mapped
# page is hit.
#
# For the SIGTRAP situation, we can raise an un-steppable GDB debugger break
# by doing syscall __NR_breakpoint.
#
# This took longer than expected, because the user interface to sigaction()
# is very different from the kernel interface to rt_sigaction().
#==============================================================================

offsets = {
# uc_mcontext
    'cpsr': 96,
    'pc': 92,
    'r11': 76,
# sigaction
    'handler': 0,
    'flags': 4,
    'restorer': 8
}

anti_debug_signal_handler = ["""
    sub  sp, #0x100
    mov  r3, #4      // SA_SIGINFO
    movt r3, #0x400  // SA_RESTORER
    str r3, [sp, #{flags}]
    eor r3, r3
1:  add r3, pc, #(handler-1b-8)

    str r3, [sp, #{handler}]
    eor r3, r3
1:  add r3, pc, #(restorer-1b-8)
    str r3, [sp, #{restorer}]
""".format(**offsets),
    shellcraft.syscall('SYS_rt_sigaction', 'SIGTRAP', 'sp', 0, 8),
    shellcraft.syscall('SYS_rt_sigaction', 'SIGSEGV', 'sp', 0, 8),
"""
    add sp, #0x100
    b after_handler
handler:
    // skip over the faulting instruction
    ldr   r3, [r2, #{cpsr}] // thumb mode?
    tst   r3, #0x20
    ldr   r3, [r2, #{pc}]   // get PC
    addne r3, r3, #2        // +=2 for thumb
    addeq r3, r3, #4        // +=4 for arm
    str   r3, [r2, #{pc}]   // store PC

    // mess around with the key a bit
    // key += 1
    // key = key ^ (key >> 1)
    ldr   r3, [r2, #{r11}]
    add   r3, r3, 1
    ror   r4, r3, #1
    eor   r3, r3, r4
    str   r3, [r2, #{r11}]
    bx    lr
restorer:
    mov r7, __NR_rt_sigreturn
    swi 0x0
after_handler:
""".format(**offsets)
]

anti_debug_signal_handler_nullderef = """
    mov   r0, 0
    ldr   r0, [r0]
"""



#==============================================================================
#                          BLOCK DEBUGGING UNDER QEMU
#==============================================================================
# Stepping over a SIGTRAP syscall is pretty annoying, without manually
# setting $PC.
#==============================================================================
anti_debugging_qemu_breakpoint = shellcraft.syscall('__ARM_NR_breakpoint')

#==============================================================================
# When running under QEMU with debugging, the GDB control socket is
# exposed as file descriptor #3 (listening socket) and as
# file descriptor #4 (established connection).
#
# This is easy to see with the 'procinfo' command of Pwndbg.
#
# pwndbg> procinfo
# ...
# fd[0]      pipe:[845385]
# fd[1]      /dev/pts/4
# fd[2]      /dev/pts/4
# fd[3]      tcp 0.0.0.0:65439 => 0.0.0.0:0 (listen)
# fd[4]      tcp 127.0.0.1:65439 => 127.0.0.1:53728 (established)
#
# We can just close the connection, or we can force GDB to appear to have
# exited by sending "$W01#b8" to FD 4.
#==============================================================================

anti_debugging_qemu_gdb = [
'''
    mov r6, sp // save stack pointer
''',
    shellcraft.write(4, "$W01#b8", 7),
'''
    mov sp, r6 // restore stack pointer
    eor r11, r11, r0 // <-- Add the result
'''
]

#==============================================================================
# Additionally, the user can specify options for debugging QEMU, like
# "-d in_asm" and "-strace" which would dump out all of our fun instructions!
#
# Let's try to stop them! -- This will not work.
#
# We will close all file descriptors, starting with STDERR, until there are
# no more file descriptors to close.  This will also close the GDB descriptors.
#==============================================================================
anti_debugging_qemu_stderr = [
'''
    mov r1, 1
CLOSE_FD_LOOP:
    add r1, 1
''',
    shellcraft.close('r1'),
'''
    eor r11, r11, r0 // <-- Add the result
    cmp r0, -9       // <-- EBADFD, Pwntools messes this up
    bne CLOSE_FD_LOOP
'''
]


#==============================================================================
#                           REQUIRE RUNNING IN QEMU
#==============================================================================
# QEMU messes up AT_HWCAP is a constant and makes it the constant 0x1fb8d7.
#==============================================================================
anti_debugging_AUXV = '''
    mov r0, sp              // Get a stack pointer
    ldr r1, [sp]            // Extract argc
    add r0, r0, r1, lsl #2  // Skip over argv
    add r0, r0, 8           // Skip over the argc itself and the NULL terminator

find_end_of_argv:           // Skip over envp
    ldr r1, [r0], #4
    cmp r1, #0
    bne find_end_of_argv

find_at_hwcap:               // Find AT_HWCAP
#define AT_HWCAP 16
    ldr r1, [r0], #4
    cmp r1, #AT_HWCAP
    bne find_at_hwcap

    ldr r1, [r0]            // r1 --> AT_HWCAP
    eor r11, r11, r1        // <-- Add to key accumulator
'''

#==============================================================================
# The stack in QEMU is always mapped at the same address, and ends at 0xf7000000.
#
# This means that at 0xf6fffff4 is the end of the name of our binary.
#
# Assuming that the filename on disk is 'superman', the last four bytes should
# be 'man\x00'.
#==============================================================================

anti_debugging_EXENAME = [
# Load from the filename
    shellcraft.mov('r0', 0xf6fffff4),
'''
    ldr r0, [r0]            // r0 --> last four bytes of filename
    eor r11, r11, r0          // <-- Add to key accumulator
''']

#==============================================================================
# QEMU will service memory accesses for the "[vectors]" page at 0xffff0000.
#
# However, it can't be dumped with GDB, and is not the "normal"
# value that you'd observe on a real ARM machine.
#
# The actual value of the entire mapping is zeroes.
#==============================================================================
anti_debugging_vectors_page_is_empty = [
# Load from __kuser_cmpxchg64 -- this is really just a '0' so a noop
    shellcraft.mov('r0', 0xffff0f60),
'''
    ldr r0, [r0]
    eor r11, r11, r0          // <-- Add to key accumulator
'''
]


#==============================================================================
#                 ENSURE THE SIGNAL HANDLER WORKS AND IS QEMU
#==============================================================================
# When using QEMU with a signal handler that does not declare SA_RESTORER,
# it will write an RT_sigreturn into the stack.
#
# Upon returning, it is still visible on the stack, as "ef9000ad".
#
# pwndbg> telescope sp-10
# 00:0000│     0xf6ffee40 —▸ 0xf6ffffa8 ◂— 0x5353454c ('LESS')
# 01:0004│     0xf6ffee44 ◂— 0x0
# 02:0008│     0xf6ffee48 ◂— 0xef9000ad
# 03:000c│     0xf6ffee4c ◂— 0x1f
# 04:0010│ sp  0xf6ffee50 ◂— 0x19
# 05:0014│     0xf6ffee54 —▸ 0xf6ffeed2 ◂— 0x62ec7176
# 06:0018│     0xf6ffee58 ◂— 0x11
# 07:001c│     0xf6ffee5c ◂— 0x64 /* 'd' */
#==============================================================================
anti_debugging_sigreturn_stack = '''
    ldr r0, [sp, #-8]
    eor r11, r11, r0
'''


#==============================================================================
#                            MORE SILLY QEMU STUFF
#==============================================================================
# We're going to load a small amount of assembly code at address 0xffff0000.
#
# This is weird for a few reasons:
#
# 1. QEMU should not allow us to mmap this page, it's the [vectors] page
# 2. QEMU should definitely not let us write to it
# 3. If QEMU lets us map it and write to it, clearly we should be able to
#.   execute the contents we wrote!
#
# However, during translation, QEMU will balk at any address >= 0xffff0000
# and generate a fault -- which will use the KUSER helpers, regardless of what
# is actually at the address.
#
# It looks like this in Pwndbg:
#
# ► 0x10000050    blx     r2
#    ↓
#   0xffff0f60    movw   r0, #0xbeef
#   0xffff0f64    movt   r0, #0xdead
#   0xffff0f68    bx     lr
#
# However, you actually end up with a SIGSEGV issued on the instruction
# which follows the BLX, and R0 is unmodified (and still contains 0xffff0f6c).
#==============================================================================
anti_debugging_qemu_traps_ffff0000_and_higher = [
    shellcraft.mmap(0xffff0000, 0x1000, 7, 'MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED', 0, 0),
    'add r0, 0xf60\n',
    'mov r2, r0\n',
]

for word in group(4, unhex('ef0e0be3ad0e4de31eff2fe1')):
    anti_debugging_qemu_traps_ffff0000_and_higher += [
        shellcraft.mov('r1', unpack(word)),
        'str r1, [r0], #4\n'
    ]

anti_debugging_qemu_traps_ffff0000_and_higher += [
    'blx r2\n',
    'eor r11, r11, r0'
]


#==============================================================================
#                         BLOCK EMULATION WITH UNICORN
#==============================================================================
# When running under an emulator like Unicorn, the stack will be
# set up, but the stack will not be "normal" i.e. the auxiliary
# vector will not be set up.
#
# Since we are running at _start, argc should be at the top of the stack.
#==============================================================================
anti_debugging_stack_top = '''
    ldr r0, [sp]
    eor r11, r11, r0
'''

#==============================================================================
#                       BLOCK RUNNING OTHER QEMU VERSIONS
#==============================================================================
# We should not be able to invoke any blacklisted syscalls.
#
# Calling getpid() is pretty benign, but we want it to return -ENOSYS.
#==============================================================================
anti_debugging_not_using_sandbox = [
    shellcraft.getpid(),
'''
    eor r11, r11, r0
'''
]

#==============================================================================
#                              GET GENERATED KEY
#==============================================================================
# We need a way to know what the key is to actually encode the payload.
#
# We cause QEMU to dump core and give us the registers
#==============================================================================
dump_core_for_key = [
    shellcraft.push('r11'),
    shellcraft.write(1, 'sp', 4),
]

#==============================================================================
#                                 XOR ENCODER
#==============================================================================

xor_encoder_loop_USERDATA = \
    shellcraft.mov('r0', 0xfffe0000) + \
'''
    add r1, r0, {length} // r1 is the 'stop' address

USERLOOP:
    ldr r3, [r0]         // load four bytes
    eor r3, {key}        // do the XOR
    str r3, [r0], #4     // store and increment

    cmp r0, r1
    bne USERLOOP
'''


xor_encoder_loop_ELFLOADER = '''
    adr r0, DATA         // r0 is the dest
    add r1, r0, {length} // r1 is the 'stop' address

LOOP:
    ldr r3, [r0]         // load four bytes
    eor r3, {key}        // do the XOR
    str r3, [r0], #4     // store and increment

    cmp r0, r1
    bne LOOP
DATA:
'''

#==============================================================================
#                          THE ACTUAL CHALLENGE CODE
#==============================================================================

with context.local(arch = 'thumb'):
    assembly = ((
        # Parse the ELF and load it into memory
        shellcraft.loader(0xfffe0000)
    ))

    if args.HELLO:
        print("Should print HELLO WORLD")
        assembly = '\n'.join((
            shellcraft.echo("HELLO, WORLD"),
            shellcraft.exit(0),
        ))

    elf_loader = asm(flat(assembly))

# Need to transition from ARM to Thumb
to_thumb = asm(shellcraft.to_thumb())
elf_loader = to_thumb + elf_loader

# Write the encoder which wraps our actual payload
encoder = xor_encoder_loop_USERDATA.format(length=4096, key='r11')
encoder += xor_encoder_loop_ELFLOADER.format(length=len(elf_loader), key='r11')

# Actually encode the ELF loader with the XOR key
XOR_KEY = unhex('3093465b')
info("xor key: %#x" % unpack(XOR_KEY))
elf_loader_xored = xor(elf_loader, XOR_KEY)
elf_loader_xored_string = '.string "%s"' % ''.join('\\x%02x' % ord(c) for c in elf_loader_xored)

# Concatenate the two
encoder_with_xored_elf_loader = encoder + elf_loader_xored_string

#==============================================================================
#                            ENCODING WITH PADDING
#==============================================================================
# Encode the antidebug shellcode with the alphanumeric encoder, and add padding
# sufficient to give us room to decode the shellcode without overwriting the
# following payload.
#==============================================================================
layers = [
    anti_debug_setup,
    anti_debug_signal_handler,
    anti_debug_signal_handler_nullderef,              # 01000080
    anti_debugging_qemu_breakpoint,                   # 01000080
    anti_debugging_qemu_gdb,                          # f7ffffff
    anti_debugging_qemu_breakpoint,                   # 01000080
    anti_debugging_qemu_stderr,                       # f7ffffff
    anti_debugging_AUXV,                              # d7b81f00
    anti_debugging_EXENAME,                           # 6d616e00
    anti_debugging_qemu_breakpoint,                   # 01000080
    anti_debugging_vectors_page_is_empty,             # 00000000
    anti_debugging_stack_top,                         # 01000000
    anti_debugging_qemu_breakpoint,                   # 01000080
    anti_debugging_qemu_traps_ffff0000_and_higher,    # 01000080
    anti_debugging_not_using_sandbox,                 # daffffff
    anti_debugging_qemu_breakpoint,                   # 01000080
    anti_debugging_sigreturn_stack,                   # 01000080
]

layers_to_encode = [
    anti_debugging_qemu_gdb,
    # anti_debugging_stack_top,
    # anti_debug_signal_handler,
    anti_debugging_qemu_stderr,
    # anti_debugging_qemu_traps_ffff0000_and_higher
]

# Generate with NOANTIDEBUG to disable anti-debugging features.
# The XOR key is manually loaded into R11.
if args.NOANTIDEBUG:
    layers = [shellcraft.mov('r11', unpack(XOR_KEY))]

if args.NOALPHA:
    alphanumeric = lambda x: x

if args.CLEAN:
    layers = [elf_loader]

# Generate with DUMPKEY to write the key to stdout.
# This is necessary if something changes in the antidebugging / keygen layers.
if args.DUMPKEY:
    layers += [dump_core_for_key, shellcraft.exit()]

# Generate with HELLO to write a message after the antidebugging has completed
if args.HELLO:
    layers.append(shellcraft.echo("Past antidebug\n"))

# Generate with NOXOR to skip the XOR-decoder and ELF loader loop, and just exit cleanly.
if not args.NOXOR:
    layers.append(encoder_with_xored_elf_loader)

# Exit cleanly at the end if something bad happened
layers.append(shellcraft.exit())

# NOTE: We must process the layers in reverse order
total = ''
for layer in layers[::-1]:
    total = asm(flat(layer)) + total

    if layer in layers_to_encode:
        total = alphanumeric(total)

    info('Length: %#x' % len(total))

# Add a few encoding layers with trash instructions
# total = alphanumeric(asm('sub r0, r0') + total)
# total = alphanumeric(asm('nop')        + total)
# total = alphanumeric(asm('eor r1, r1') + total)
total = alphanumeric(total)
info('Final length: %#x' % len(total))
#==============================================================================
#                               RANDOM FUN STUFF
#==============================================================================
# Let's toss some interesting strings at the end of the file, which do nothing.
#
# However, these are extremely necessary in order to give us a bunch of
# breathing room for decoding.
#==============================================================================
strings = [
# Who knows if they'll notice this
    'UPX!\x00',
# Strings from the linker
    'TLS generation counter wrapped!  Please report as described in <https://bugs.launchpad.net/ubuntu/+source/glibc/+bugs>.\x00',
# XZ-compressed copy of a dumb elf file
    '\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F\x02\x00!\x01\x1c\x00\x00\x00\x10\xcfX\xcc\xe0\x01\xb3\x00\xdb]\x00?\x91E\x84h;\xde\xde\xa6\x0f#\xf0\xd4$\x19\x96P\x81_z\xd7\xb1\xb7\x7f \xcf9\xfa\xb9AY{\x052\x19[\']\xfew\xffJ\xc2\xae\xff\xba\xba\xb2Z\xd7o\x88\x97L\xe2i\x9asH/\xdc5\xbe\xa3`\xbb\x9fN\x89A\xb6$\xb7K\xdb\x1cF\xba\xe1\xda\xed\xe7\xe7\\\xf3;\xa2\x93\x8cL\x92|-\xd8\x1c\xf2\xee\xe0y.\xb9\xbd;\xbd\x19\xfaq\x15\x83z\x83\xbb\xa4\x13\x7f{\xe5\xf1=\xbf\x15[\xb2\x1cPl\x0f\xfb\x15Wf\x03w.\xecw\x0b\xbc\xd9-\x8b\'\xc9.yj\xce\xa8j\x19\xd3\x90whr\xc9 \xd8\xcb*3\xb0u\xac\x7f\xf0\x18h\xee\x9e\xf1\xbb\xfd\x90\x13A\xedI##\xab_v\xd7h\xc3\xech&dr\x95RWG\xb0f\xff\xad\xc6\x99)n\xc0<\x12\x88\xea\xaf=~\xce\xca\xc8\x0f!Z\x1f\x00\x00\x00\xde\xf2\xe9"0\x7f%#\x00\x01\xf7\x01\xb4\x03\x00\x00X\xb3\xf4f\xb1\xc4g\xfb\x02\x00\x00\x00\x00\x04YZ'
]

total += ''.join(strings)

with context.local(arch='thumb'):
    read_elf_to_fffe0000 = \
        shellcraft.mmap(0xfffe0000, 0x1000, 'PROT_READ | PROT_WRITE', 'MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED', 0, 0) \
        + shellcraft.readn(0, 0xfffe0000, 4096) \
        + shellcraft.to_arm()
    read_elf_to_fffe0000 = asm(read_elf_to_fffe0000)

ELF.from_bytes(read_elf_to_fffe0000 + total, shared=True, arch='thumb').save('superman')
os.chmod('superman', 0o755)

"""
Packet received: OK
Sending packet: $vCont;c:0#12...Ack
Packet received: E22
warning: Remote failure reply: E22
"""

