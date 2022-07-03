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

import lief
import binascii
import math

DEBUG = False

prg = lief.parse('main')

def print_obj(obj):
    print('\n'.join([" - %s = %s" % (x, getattr(obj, x)) for x in dir(obj) if x[0] != "_"]))

def u64(val):
    return int(binascii.hexlify(val.ljust(8, b'\0')[::-1]), 16)

def p32(val):
    return binascii.unhexlify("%08x"%val)[::-1]

symbol_start_magic = b'SYMBLBEG'
reloc_start_magic = b'RELOCBEG'
dummy_dst_addr = 0x4141414141414141

regs = []
for i in range(10):
    # u4 name, u1 info, u1 other, u2 shndx, u8 value, u8 size
    s = lief.ELF.Symbol()
    s.name = chr(i + 1)
    s.value = dummy_dst_addr
    s.size = 8
    s.exported = False
    s.shndx = 1
    s.type = lief.ELF.SYMBOL_TYPES.OBJECT
    s.visibility = lief.ELF.SYMBOL_VISIBILITY.DEFAULT
    regs.append(prg.add_dynamic_symbol(s))

relocs = []
for i in range(102000):
    # u8 addr, u8 info, u8 addend
    relocs.append(prg.add_dynamic_relocation(lief.ELF.Relocation(dummy_dst_addr, type=lief.ELF.RELOCATION_X86_64.RELATIVE, is_rela=True, addend=0)))

regs[0].value = u64(symbol_start_magic)
relocs[0].address = u64(reloc_start_magic)

prg.write('main2')

with open('main2', 'rb') as f: main2 = f.read()

# hack to fix some bug
prg = lief.parse('main2')
dynsym = prg.get_section('.dynsym')
dynsym_seg = list(dynsym.segments)[0]
dynsym_seg.add(lief.ELF.SEGMENT_FLAGS.W)
dynsym_seg.add(lief.ELF.SEGMENT_FLAGS.X)

serial_addr = prg.get_symbol('serial').value
fail_addr = prg.get_symbol('fail').value
default_addr = dynsym_seg.virtual_address

reg_base_addr = prg.offset_to_virtual_address(main2.index(symbol_start_magic) - 8) # -8 = u4 name, u1 info, u1 other, u2 shndx
reloc_base_addr = prg.offset_to_virtual_address(main2.index(reloc_start_magic))

regs = [s for s in prg.symbols if s.value == u64(symbol_start_magic) or s.value == dummy_dst_addr]
relocs = [r for r in prg.relocations if r.address == u64(reloc_start_magic) or r.address == dummy_dst_addr]

for r in regs:
    r.value = default_addr

for r in relocs:
    r.address = default_addr

iReg = 0
iReloc = 0

print("reg_base_addr = %x, reloc_base_addr = %x" % (reg_base_addr, reloc_base_addr))

def alloc_reg():
    global iReg
    iReg += 1
    return iReg - 1

def dealloc_regs(count):
    global iReg
    iReg -= count

def get_reg_value_ptr(idx):
    return reg_base_addr + idx * 0x18 + 0x8

def get_reg_size_ptr(idx):
    return reg_base_addr + idx * 0x18 + 0x10

def get_reg_ptr(idx):
    return reg_base_addr + idx * 0x18

def get_reloc_addr_ptr(idx):
    return reloc_base_addr + idx * 0x18

def get_reloc_addend_ptr(idx):
    return reloc_base_addr + idx * 0x18 + 0x10

def next_reloc():
    global iReloc
    r = relocs[iReloc]
    iReloc += 1
    return r

def logging(is_enabled):
    if not DEBUG:
        return
    r = next_reloc()
    r.type = 0x1337
    r.addend = 2 if is_enabled else 3

def overwrite(addr, value):
    r = next_reloc()
    r.type = lief.ELF.RELOCATION_X86_64.RELATIVE
    r.address = addr
    if value >= 0x8000000000000000:
        value -= 0x10000000000000000
    r.addend = value

reg_zero = regs[alloc_reg()]
reg_zero.value = 0

def overwrite32(addr, value):
    r = next_reloc()
    r.type = lief.ELF.RELOCATION_X86_64.R32
    r.address = addr
    r.symbol = reg_zero
    if value >= 0x80000000:
        value -= 0x100000000
    r.addend = value

def copy_sym(sym, to_addr):
    r = next_reloc()
    r.type = lief.ELF.RELOCATION_X86_64.COPY
    r.address = to_addr
    r.symbol = sym

def copy_reg(reg_idx, to_addr):
    copy_sym(regs[reg_idx], to_addr)

copy_last_from_addr = -1
copy_last_size = -1

reg_copy = alloc_reg()

def copy_prep(from_addr, size):
    global copy_last_from_addr
    if copy_last_from_addr != from_addr:
        overwrite(get_reg_value_ptr(reg_copy), from_addr)
    copy_last_from_addr = from_addr

    global copy_last_size
    if copy_last_size != size:
        overwrite(get_reg_size_ptr(reg_copy), size)
    copy_last_size = size

def copy_do(to_addr):
    copy_reg(reg_copy, to_addr)

def copy(from_addr, to_addr, size):
    copy_prep(from_addr, size)
    copy_do(to_addr)

def add(to_addr, reg_idx, value):
    r = next_reloc()
    r.type = lief.ELF.RELOCATION_X86_64.R64
    r.address = to_addr
    r.symbol = regs[reg_idx]
    r.addend = value

def reg_addition(to_addr, reg_idx, value_addr):
    copy_prep(value_addr, 8)
    add_addend_ptr = get_reloc_addend_ptr(iReloc + 1)
    copy_do(add_addend_ptr)
    add(to_addr, reg_idx, 0)
    overwrite(add_addend_ptr, 0)

def reg_to_dyn_addr(reg_idx, to_addr_ptr):
    copy_prep(to_addr_ptr, 8)
    copy_reg_address_ptr = get_reloc_addr_ptr(iReloc + 1)
    copy_do(copy_reg_address_ptr)

    r = next_reloc()
    r.type = lief.ELF.RELOCATION_X86_64.R64
    r.address = 0
    r.symbol = regs[reg_idx]
    r.addend = 0

def add_regs_to(to_addr, reg1_idx, reg2_idx):
    reg_addition(to_addr, reg1_idx, get_reg_value_ptr(reg2_idx))

def add_regs(to_reg_idx, reg1_idx, reg2_idx):
    reg_addition(get_reg_value_ptr(to_reg_idx), reg1_idx, get_reg_value_ptr(reg2_idx))

def inc_reg(reg_idx, inc_reg_idx):
    reg_addition(get_reg_value_ptr(reg_idx), reg_idx, get_reg_value_ptr(inc_reg_idx))

def inc_reg_with_value(reg_idx, value_addr):
    reg_addition(get_reg_value_ptr(reg_idx), reg_idx, value_addr)

reg_rce_id = alloc_reg()
reg_rce = regs[reg_rce_id]

def call_func(to_addr, func_addr):
    overwrite(get_reg_value_ptr(reg_rce_id), func_addr)
    overwrite(get_reg_ptr(reg_rce_id), 0x0001000A0000001A)
    r = next_reloc()
    r.type = lief.ELF.RELOCATION_X86_64.R64
    r.addend = 0
    r.address = to_addr
    r.symbol = reg_rce
    #reg_rce.value = func_addr

# turn on logging
logging(True)

def reloc_wipe(addr, count):
    # wipe data from memory by copying empty entries from the end of reloc entries
    from_reloc = len(relocs) - count
    if from_reloc <= iReloc:
        raise Exception("There is not enough empty relocs at the end to copy... Increase generated reloc count (generated=%d, used=%d, empty=%d, needed=%d)!" % (len(relocs), iReloc, len(relocs) - iReloc, count))
    #print("reloc_wipe(addr=%x, count=%d -> size=%d, from=%x)" % (addr, count, count*0x18, reloc_base_addr + from_reloc*0x18))
    copy(reloc_base_addr + from_reloc*0x18, addr, count*0x18)

def alloc_buffer(bytesize):
    global iReloc
    ptr = get_reloc_addr_ptr(iReloc)
    iReloc += math.ceil(bytesize / 0x18)
    return ptr

def wipe_buffer(ptr, bytesize):
    reloc_wipe(ptr, math.ceil(bytesize / 0x18))

def run_code(asm, result_addr=None):
    asm += b'\xc3' # ret

    vals = [u64(asm[i:i+8]) for i in range(0, len(asm), 8)]

    datasize = math.ceil(len(asm) / 8) * 8
    dataptr = alloc_buffer(datasize)
    print("injecting asm byte code to 0x%x (len=%d): %s" % (dataptr, len(asm), ' '.join(["%02x"%x for x in asm])))

    for i in range(len(vals)):
        overwrite(dataptr + i*8, vals[i])

    call_func(result_addr if result_addr else dataptr, dataptr)
    wipe_buffer(dataptr, datasize)

def run_code_arg1(asm, arg1, result_addr=None):
    # 0:  48 c7 c7 44 33 22 11    mov    rdi,0x11223344
    asm = b'\x48\xc7\xc7' + p32(arg1) + asm
    run_code(asm, result_addr)

def set_reg(reg_idx, value):
    overwrite(get_reg_value_ptr(reg_idx), value)

def add_reg_const(reg_idx, const_value):
    add(get_reg_value_ptr(reg_idx), reg_idx, const_value)

def set_reg_from_addr(reg_idx, addr):
    copy(addr, get_reg_value_ptr(reg_idx), 8)

def eq_mul_op(reg_char, reg_multi, rnd):
    set_reg(reg_multi, 0)

    # converts eg. 11*x to ((x*2)*2 + x)*2 + x
    ops = [x=='1' for x in bin(rnd)[2:]]
    for op in ops:
        inc_reg(reg_multi, reg_multi)
        if op:
            inc_reg(reg_multi, reg_char)

def eq_asm_op(reg_char, op, rnd):
    if op == 11: # XOR
        # 80 34 25 44 43 42 41 23   xor    BYTE PTR ds:0x41424344,0x23
        prefix = b'\x80\x34\x25'
    elif op == 12: # OR
        # 80 0c 25 44 43 42 41 23   or     BYTE PTR ds:0x41424344,0x23
        prefix = b'\x80\x0c\x25'
    elif op == 13: # AND
        # 80 24 25 44 43 42 41 23   and    BYTE PTR ds:0x41424344,0x23
        prefix = b'\x80\x24\x25'
    elif op == 14: # ROL
        # c0 04 25 44 43 42 41 23   rol    BYTE PTR ds:0x41424344,0x23
        prefix = b'\xc0\x04\x25'
    elif op == 15: # ROR
        # c0 0c 25 44 43 42 41 23   ror    BYTE PTR ds:0x41424344,0x23
        prefix = b'\xc0\x0c\x25'
    elif op == 16: # ADD
        # 80 04 25 44 43 42 41 23   add    BYTE PTR ds:0x41424344,0x23
        prefix = b'\x80\x04\x25'
    elif op == 17: # SUB
        # 80 2c 25 44 43 42 41 23   sub    BYTE PTR ds:0x41424344,0x23
        prefix = b'\x80\x2c\x25'
    elif op == 18: # SHL
        # c0 24 25 44 43 42 41 23   shl    BYTE PTR ds:0x41424344,0x23
        prefix = b'\xc0\x24\x25'
    elif op == 19: # SHR
        # c0 2c 25 44 43 42 41 23   shr    BYTE PTR ds:0x41424344,0x23
        prefix = b'\xc0\x2c\x25'
    else: # MUL
        raise Exception("Not supported op: %s", op)

    reg_char_addr = get_reg_value_ptr(reg_char)
    bytecode = prefix + p32(reg_char_addr) + bytes([rnd])
    run_code(bytecode)

def do_eq(reg_result, config, enc_flag_addr):
    rnds = config["rnds"]
    ops = config["ops"]
    sums = config["sums"]

    reg_char = alloc_reg()
    reg_op_res = alloc_reg()
    reg_sum = alloc_reg()

    set_reg(reg_char, 0)

    for eq_idx in range(len(rnds)):
        eq_rnds = rnds[eq_idx]
        eq_ops = ops[eq_idx]
        eq_sum = sums[eq_idx]

        set_reg(reg_sum, -eq_sum)

        for i in range(len(eq_rnds)):
            op = eq_ops[i]
            rnd = eq_rnds[i]

            copy(enc_flag_addr + i, get_reg_value_ptr(reg_char), 1)

            if op <= 10:
                eq_mul_op(reg_char, reg_op_res, rnd)
                inc_reg(reg_sum, reg_op_res)
            else:
                eq_asm_op(reg_char, op, rnd)
                inc_reg(reg_sum, reg_char)

        # Zero out the 5 MSB bytes, so negative values are not allowed,
        #   so every equation should be zero (reg_sum) to make reg_sum zero.
        # Why 5 bytes? 4 bytes is not enough, because the "fail" variable is only 4 bytes.
        #  6 bytes is too much (2 bytes left), because the sum can be > 65536.
        copy(get_reg_value_ptr(reg_char) + 3, get_reg_value_ptr(reg_sum) + 3, 5)
        inc_reg(reg_result, reg_sum)

    dealloc_regs(3)

def deref_arr(dest_reg, arr_ptr_const, idx, item_size):
    if item_size != 8:
        raise Exception("not supported item_size")

    # dest_reg = idx + idx = 2 * idx
    add_regs(dest_reg, idx, idx)
    # dest_reg = dest_reg + dest_reg = 4 * idx
    inc_reg(dest_reg, dest_reg)
    # dest_reg = dest_reg + dest_reg = 8 * idx
    inc_reg(dest_reg, dest_reg)
    # dest_reg = &arr_ptr_const[dest_reg] = &arr_ptr_const[8 * idx]
    add(get_reg_value_ptr(dest_reg), dest_reg, arr_ptr_const)
    return dest_reg

def rc4_prng(key_addr, key_len, out_char_len):
    Sptr = alloc_buffer(256 * 8)
    if key_len % 2 != 0:
        raise Exception("Key len must be dividable by two!")
    output_buf = alloc_buffer(key_len // 2 * out_char_len)
    j = alloc_reg()
    Sj_ptr = alloc_reg()
    tmp = alloc_reg()
    tmp2 = key_char = alloc_reg()

    # S = 0x8042b6, j = 0x8040dc, &Sj = 0x8040f4, tmp = 0x80410c, tmp2 = key_char = 0x804124, output_buf = 0x804ac6
    print("S = 0x%x, j = 0x%x, &Sj = 0x%x, tmp = 0x%x, tmp2 = key_char = 0x%x, output_buf = 0x%x" %
        (Sptr, get_reg_value_ptr(j), get_reg_value_ptr(Sj_ptr), get_reg_value_ptr(tmp),
        get_reg_value_ptr(key_char), output_buf))

    for key_pos in range(0, key_len, 2):
        for i in range(256):
            overwrite(Sptr + i * 8, i)

        set_reg(j, 0)

        for i in range(256):
            Si_ptr = Sptr + i*8

            # j += S[i]
            inc_reg_with_value(j, Si_ptr)
            # key_char = serial[i % 2] % 256
            copy(key_addr + key_pos + i % 2, get_reg_value_ptr(key_char), 1)
            # j += key_char
            inc_reg(j, key_char)
            # j %= 256
            overwrite32(get_reg_value_ptr(j) + 1, 0)

            # tmp = S[i]
            set_reg_from_addr(tmp, Si_ptr)

            # Sj_ptr = &S[j]
            deref_arr(Sj_ptr, Sptr, j, 8)
            # S[i] = *Sj = S[j]
            copy_reg(Sj_ptr, Si_ptr)

            # S[j] = tmp
            reg_to_dyn_addr(tmp, get_reg_value_ptr(Sj_ptr))

        set_reg(j, 0)

        for i in range(3):
            Si_ptr = Sptr + i*8

            # j += S[i]
            inc_reg_with_value(j, Si_ptr)
            # j %= 256
            overwrite32(get_reg_value_ptr(j) + 1, 0)

            # tmp = S[i]
            set_reg_from_addr(tmp, Si_ptr)

            # Sj_ptr = &S[j]
            deref_arr(Sj_ptr, Sptr, j, 8)
            # S[i] = *Sj = S[j]
            copy_reg(Sj_ptr, Si_ptr)

            # tmp2 = S[j]
            set_reg_from_addr(tmp2, Si_ptr)

            # S[j] = tmp = S[i]
            reg_to_dyn_addr(tmp, get_reg_value_ptr(Sj_ptr))

            # tmp = tmp + tmp2 = S[i] + S[j]
            inc_reg(tmp, tmp2)
            # tmp %= 256
            overwrite32(get_reg_value_ptr(tmp) + 1, 0)

            # Sj_ptr = &S[tmp]
            deref_arr(Sj_ptr, Sptr, tmp, 8)
            # S[i] = *Sj = S[j]
            copy_reg(Sj_ptr, output_buf + key_pos // 2 * out_char_len + i)

    wipe_buffer(Sptr, 256 * 8)
    dealloc_regs(4)
    return output_buf

def check_charset(reg_result, serial_addr):
    reg_check_res = alloc_reg()
    set_reg(reg_check_res, 0)
    with open("charset_check.bin", "rb") as f: asm = bytearray(f.read())
    run_code_arg1(asm, serial_addr, get_reg_value_ptr(reg_check_res))
    inc_reg(reg_result, reg_check_res)
    dealloc_regs(1)

def calc_fail(reg_result, fail_addr):
    # 8b 04 25 44 33 22 11    mov    eax,DWORD PTR ds:0x11223344
    # f7 d8                   neg    eax
    # 19 c0                   sbb    eax,eax
    reg_result_addr = get_reg_value_ptr(reg_result)
    asm = b'\x8b\x04\x25' + p32(reg_result_addr) + b'\xf7\xd8\x19\xc0'
    run_code(asm, reg_result_addr)
    copy(reg_result_addr, fail_addr, 8)

import flag_data

FLAG1_LEN = len(flag_data.flag1["value"])
FLAG2_LEN = len(flag_data.flag2["value"])

enc_flag1_addr = rc4_prng(serial_addr, FLAG1_LEN, 3)
enc_flag1_len = FLAG1_LEN // 2 * 3

reg_result = alloc_reg()
set_reg(reg_result, 0)

do_eq(reg_result, flag_data.flag1, enc_flag1_addr)
reloc_wipe(enc_flag1_addr, enc_flag1_len)

check_charset(reg_result, serial_addr)

do_eq(reg_result, flag_data.flag2, serial_addr + FLAG1_LEN)

overwrite(fail_addr, 0)
calc_fail(reg_result, fail_addr)

# turn off logging
logging(False)

print("Used reloc entry count: %d" % iReloc)
prg.write('eldar')
