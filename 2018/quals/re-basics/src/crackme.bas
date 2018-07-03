# Copyright 2018 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
#
# Source-code of the "Back to The BASICs" CrackMe (Google CTF 2018 Quals).
# Author: Gynvael Coldwind (gynvael@google.com)
#
# This file needs to be compiled by CrackBASIC (see crackbasic.py file).
#
# Some fun facts:
# - C64 BASIC V2 tries to "repair" loaded BASIC programs when loading them by
#   making sure the linked list doesn't have any 'weird' pointers. Such pointers
#   are replaced by whatever is the result of:
#     addr_of_prev_line + strlen(line) + 1
#   Where "strlen" is basically a standard ASCIIZ (PETSCIIZ?) strlen.
#   To bypass this we're slashing ("ending") the list just before stuff gets
#   funny. The list has to be "re-attached" at runtime due to this.
# - There are 19 chunks using line numbers 2000-2999. I'm switching between them
#   at runtime by changing the "next" pointers in the linked list. These chunks
#   at rest, and when not used (before executions, after execution) are
#   "encrypted" (well, XORed).
# - Most of the time when checking the password the linked list has a cycle/loop
#   at line 2000, so if anyone pauses the execution and runs LIST command, they
#   will get an infinite listing.
# - C64 BASIC uses 40-bit floats. The math in this crackme abuses that fact and
#   basically does bitwise operations using "weird looking" 40-bit floats (well,
#   in binary form these floats don't look weird at all). The math / values from
#   this listing cannot be directly used in x86 floats (32-, 64-, 80-bits) as
#   the fraction part has a different size and (due to the values I've chosen)
#   will yield different results.

1 rem ======================
2 rem === back to basics ===
3 rem ======================

# Some colors.
# Useful link: https://www.c64-wiki.com/wiki/Color
10 ?chr$(155):?chr$(147)
20 poke &D020, 6:poke &D021, 6:
25 ?"loading..."


30 data &02,&01,&03,&0b,&20,&20,&51,&51,&51,&20,&20,&20,&20,&51,&20,&20,&20,&20,&51,&51,&51,&51,&20,&51,&51,&51,&51,&51,&20,&20,&51,&51,&51,&51,&20,&20,&57,&57,&57,&57
31 data &20,&20,&20,&20,&20,&20,&51,&20,&20,&51,&20,&20,&51,&20,&51,&20,&20,&51,&20,&20,&20,&20,&20,&20,&20,&51,&20,&20,&20,&51,&20,&20,&20,&20,&20,&57,&20,&20,&20,&20
32 data &14,&0f,&20,&20,&20,&20,&51,&51,&51,&20,&20,&51,&20,&20,&20,&51,&20,&20,&51,&51,&51,&20,&20,&20,&20,&51,&20,&20,&20,&51,&20,&20,&20,&20,&20,&20,&57,&57,&57,&20
33 data &20,&20,&20,&20,&20,&20,&51,&20,&20,&51,&20,&51,&51,&51,&51,&51,&20,&20,&20,&20,&20,&51,&20,&20,&20,&51,&20,&20,&20,&51,&20,&20,&20,&20,&20,&20,&20,&20,&20,&57
34 data &14,&08,&05,&20,&20,&20,&51,&51,&51,&20,&20,&51,&20,&20,&20,&51,&20,&51,&51,&51,&51,&20,&20,&51,&51,&51,&51,&51,&20,&20,&51,&51,&51,&51,&20,&57,&57,&57,&57,&20

40 for i = 0 to 39: poke 55296 + i, 1: next i
41 for i = 40 to 79: poke 55296 + i, 15: next i
42 for i = 80 to 119: poke 55296 + i, 12: next i
43 for i = 120 to 159: poke 55296 + i, 11: next i
44 for i = 160 to 199: poke 55296 + i, 0: next i

50 for i = 0 to 199
51 read c : poke 1024 + i, c
52 next i

60 ?:?:?:?:?
70 poke 19,1: ?"password please?" chr$(5): input ""; p$: poke 19,0

80 ?:?:?chr$(155) "processing... (this might take a while)":?"[                    ]"
90 chkoff = 11 * 40 + 1

# Check length.
200 if len(p$) = 30 then goto 250
210 poke 1024 + chkoff + 0, 86:poke 55296 + chkoff + 0, 10
220 goto 31337
250 poke 1024 + chkoff + 0, 83:poke 55296 + chkoff + 0, 5

# Re-attach the slashed list around here.
2000 rem never gonna give you up
2001 rem

# Attach the first checker.
2010 poke {rawaddr 2000 0 W __default}, {rawaddr 2001 0 L check0} : poke {rawaddr 2000 1 W __default}, {rawaddr 2001 0 H check0} : goto 2001

31337 ?:?"verdict: nope":goto 31345
31345 goto 31345
# Slash the list after next line.
.slash_list
31346 rem

# Run "genprog.py > CHECKERS.BAS" to (re-)generate this part.
.include CHECKERS.BAS

.label checkend
2000 rem
2001 rem

# Attach the final check code.
# Do the final check.
31337 t = t0 + t1 + t2 + t3 + t4 + t5 + t6 + t7 + t8 + t9 + ta + tb + tc + td + te + tf + tg + th + tj
31338 if t = -19 then goto 31340
31339 ?:?"verdict: nope":goto 31345
31340 ?:?"verdict: correct"

31345 goto 31345
# Slash the list after next line.
.slash_list
31346 rem

