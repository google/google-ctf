/*
 * Copyright (C) 2020 Google LLC
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

.text

.globl start
.p2align 8
start:
  { allocframe(sp, #0):raw }
  { call welcome  }

  // This is skipped at runtime. Correct r0 for unmask loop is |main|'s offset (0x28).
  { r0 = #0x1337    }

  // Unmask data strings and target ciphertext.
  { r1 = ##target }
  { loop0(1f, #80) }
1:
  { r2 = memb(r1)  }
  { r2 = xor(r0, r2)
   memb(r1++#1) = r2.new
    r0 = add(r0, #1) }:endloop0

main:
  { call read_flag  }
  { call check_flag }
  { call print_status }
  { call exit }
  { dealloc_return }

exit:
  { r6 = #94  } // __NR_exit_group
  { r0 = #0   }
  { trap0(#1) }
  { jumpr lr  }

welcome:
  { allocframe(sp, #0):raw }
  { r7 = memw(fp+#4) }
  { r6 = #64   } // __NR_write
  { r0 = #1    } // STDOUT
  { r1 = ##hello }
  { r2 = #4   }
  { trap0(#1)  }
  // return value (r0) is the number of bytes written (4).
  // 4 = 0x08 ^ 0x0c, so the following xor changes the return address
  // from 0x??????08 to 0x??????0c and skips the r0 initialization right
  // after the { call welcome } packet.
  { r0 = xor(r7, r0) }
  // r0 pointing to main is a decoy: the old r0 is written (xor result),
  // and not r0.new.
  { memw(sp+#4) = r0
    r0 = ##main }
  { dealloc_return }

read_flag:
  { r6 = #63   } // __NR_read
  { r0 = #0    } // STDOUT
  { r1 = ##flag }
  { r2 = #8    }
  { trap0(#1)  }

  { jumpr lr   }

print_status:
  { r0 = and(r0, #0xff) }
  { p0 = cmp.eq(r0, #0xff); if (!p0.new) jump:t 1f }
  { r1 = ##good }
  { r2 = #61   }
  { jump 2f    }
1:
  { r1 = ##bad }
  { r2 = #11   }
2:
  { r6 = #64   } // __NR_write
  { r0 = #1    } // STDOUT
  { trap0(#1)  }
  { jumpr lr   }

check_flag:
  { allocframe(sp, #0):raw }

  // Read flag LE words: L0 || R0
  //   r2 <- L0
  //   r3 <- R0
  { r3:2 = memd(##flag) }

  // Hardcoded numbers below (r0) encode the following hint:
  //   "* google binja-hexagon *"
  //
  // Numbers passed to hex functions (r1) are a sequence of
  // Hexagonal numbers: 1, 6, 15, 28, 45, 66, 91, 120, 153, 190
  // https://en.wikipedia.org/wiki/Hexagonal_number

  // Transform flag. All hex functions are bijective.
  { r0 = #1869029418 }
  { r0 = r2; r2 = r0 }
  { r1 = #1  }
  { call hex1 }
  { r2 = xor(r2, r0) }

  { r0 = #1701603183 }
  { r0 = r3; r3 = r0 }
  { r1 = #6  }
  { call hex2 }
  { r3 = xor(r3, r0) }


  // A Feistel network with custom key round functions and simple xor cipher function.
  // This network was chosen because its data flow resembles a series
  // of hexagons (https://en.wikipedia.org/wiki/File:Feistel_cipher_diagram_en.svg).
  //

  // Round 1.
  { r0 = #1852400160 }
  { r1 = #15  }
  { call hex3 }
  { r0 = xor(r0, r3) }
  { r2 = r3; r3 = xor(r2, r0) }

  // Round 2.
  { r0 = #1747804522 }
  { r1 = #28  }
  { call hex4 }
  { r0 = xor(r0, r3) }
  { r2 = r3; r3 = xor(r2, r0) }

  // Round 3.
  { r0 = #1734441061 }
  { r1 = #45  }
  { call hex5 }
  { r0 = xor(r0, r3) }
  { r2 = r3; r3 = xor(r2, r0) }

  // Round 4.
  { r0 = #706768495 }
  { r1 = #66  }
  { call hex6 }
  { r0 = xor(r0, r3) }
  { r2 = r3; r3 = xor(r2, r0) }

  // Compare result with target value.
  { r5:4 = memd(##target) }
  { p0 = cmp.eq(r5:4, r3:2) }
  { r0 = p3:0 }

  { dealloc_return }

.section .data
hello:
  .string "Hi!\n"
  .size hello, 4

flag:
  .byte 0, 0, 0, 0, 0, 0, 0, 0

target:
  # The first mask key is the LSB of |main|.
  # Target ciphertext found using bn_solution.py:
  # $ ./bn_solution.py build/challenge  -r
  .byte 0x28 ^ 0x97
  .byte 0x29 ^ 0xbf
  .byte 0x2a ^ 0x80
  .byte 0x2b ^ 0x6d
  .byte 0x2c ^ 0x3d
  .byte 0x2d ^ 0xe
  .byte 0x2e ^ 0x45
  .byte 0x2f ^ 0x9d

good:
  # Masked "Congratulations!\n"
  # These strings are masked to give players a hint on the
  # |target|'s mask key.
  #
  # def MaskMsg(start, msg):
  #   return [".byte 0x{0:x} ^ 0x{1:x}".format(start+i, ord(b)) for i,b in enumerate(msg)]
  #
  # MaskMsg(0x30, "Congratulations! Flag is 'CTF{XXX}' where XXX is your input.\n")
 .byte 0x30 ^ 0x43
 .byte 0x31 ^ 0x6f
 .byte 0x32 ^ 0x6e
 .byte 0x33 ^ 0x67
 .byte 0x34 ^ 0x72
 .byte 0x35 ^ 0x61
 .byte 0x36 ^ 0x74
 .byte 0x37 ^ 0x75
 .byte 0x38 ^ 0x6c
 .byte 0x39 ^ 0x61
 .byte 0x3a ^ 0x74
 .byte 0x3b ^ 0x69
 .byte 0x3c ^ 0x6f
 .byte 0x3d ^ 0x6e
 .byte 0x3e ^ 0x73
 .byte 0x3f ^ 0x21
 .byte 0x40 ^ 0x20
 .byte 0x41 ^ 0x46
 .byte 0x42 ^ 0x6c
 .byte 0x43 ^ 0x61
 .byte 0x44 ^ 0x67
 .byte 0x45 ^ 0x20
 .byte 0x46 ^ 0x69
 .byte 0x47 ^ 0x73
 .byte 0x48 ^ 0x20
 .byte 0x49 ^ 0x27
 .byte 0x4a ^ 0x43
 .byte 0x4b ^ 0x54
 .byte 0x4c ^ 0x46
 .byte 0x4d ^ 0x7b
 .byte 0x4e ^ 0x58
 .byte 0x4f ^ 0x58
 .byte 0x50 ^ 0x58
 .byte 0x51 ^ 0x7d
 .byte 0x52 ^ 0x27
 .byte 0x53 ^ 0x20
 .byte 0x54 ^ 0x77
 .byte 0x55 ^ 0x68
 .byte 0x56 ^ 0x65
 .byte 0x57 ^ 0x72
 .byte 0x58 ^ 0x65
 .byte 0x59 ^ 0x20
 .byte 0x5a ^ 0x58
 .byte 0x5b ^ 0x58
 .byte 0x5c ^ 0x58
 .byte 0x5d ^ 0x20
 .byte 0x5e ^ 0x69
 .byte 0x5f ^ 0x73
 .byte 0x60 ^ 0x20
 .byte 0x61 ^ 0x79
 .byte 0x62 ^ 0x6f
 .byte 0x63 ^ 0x75
 .byte 0x64 ^ 0x72
 .byte 0x65 ^ 0x20
 .byte 0x66 ^ 0x69
 .byte 0x67 ^ 0x6e
 .byte 0x68 ^ 0x70
 .byte 0x69 ^ 0x75
 .byte 0x6a ^ 0x74
 .byte 0x6b ^ 0x2e
 .byte 0x6c ^ 0xa


bad:
  # Masked "Try again!\n"
  # MaskMsg(0x6d, "Try again!\n")
 .byte 0x6d ^ 0x54
 .byte 0x6e ^ 0x72
 .byte 0x6f ^ 0x79
 .byte 0x70 ^ 0x20
 .byte 0x71 ^ 0x61
 .byte 0x72 ^ 0x67
 .byte 0x73 ^ 0x61
 .byte 0x74 ^ 0x69
 .byte 0x75 ^ 0x6e
 .byte 0x76 ^ 0x21
 .byte 0x77 ^ 0xa

