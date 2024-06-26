#!/usr/bin/env python3
# Copyright 2024 Google LLC
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

r.send(b"""3
t1^ A B
3
t2^ A t1^
3
t3^ t1^ B
3
t4 t2^ t3^
3
t5^ t4 C
3
t6^ t4 t5^
3
t7^ t5^ C
3
t8 t6^ t7^
3
t9 t1^ t5^
3
S1 t8 t8
3
S_tentative S1 S1
3
C1^ t9 t9
3
Cout_tentative C1^ C1^
3
u1^ data clk^
3
u0 data data
3
u2^ u0 clk^
3
u3 u1^ u4^
3
u4^ u3 u2^
3
u9 u3 u3
3
u5^ u3 nclk
3
u6 u9 nclk
3
copy0_u7 u5^ copy0_u8^
3
copy0_u8^ copy0_u7 u6
3
copy1_u1^ copy0_u7 clk^
3
copy1_u2^ copy0_u8^ clk^
3
copy1_u3 copy1_u1^ copy1_u4^
3
copy1_u4^ copy1_u3 copy1_u2^
3
copy1_u9 copy1_u3 copy1_u3
3
copy1_u5^ copy1_u3 nclk
3
copy1_u6 copy1_u9 nclk
3
copy1_u7 copy1_u5^ copy1_u8^
3
copy1_u8^ copy1_u7 copy1_u6
3
copy2_u1^ copy1_u7 clk^
3
copy2_u2^ copy1_u8^ clk^
3
copy2_u3 copy2_u1^ copy2_u4^
3
copy2_u4^ copy2_u3 copy2_u2^
3
copy2_u9 copy2_u3 copy2_u3
3
copy2_u5^ copy2_u3 nclk
3
copy2_u6 copy2_u9 nclk
3
copy2_u7 copy2_u5^ copy2_u8^
3
copy2_u8^ copy2_u7 copy2_u6
3
copy3_u1^ copy2_u7 clk^
3
copy3_u2^ copy2_u8^ clk^
3
copy3_u3 copy3_u1^ copy3_u4^
3
copy3_u4^ copy3_u3 copy3_u2^
3
copy3_u9 copy3_u3 copy3_u3
3
copy3_u5^ copy3_u3 nclk
3
copy3_u6 copy3_u9 nclk
3
copy3_u7 copy3_u5^ copy3_u8^
3
copy3_u8^ copy3_u7 copy3_u6
3
copy4_u1^ copy3_u7 clk^
3
copy4_u2^ copy3_u8^ clk^
3
copy4_u3 copy4_u1^ copy4_u4^
3
copy4_u4^ copy4_u3 copy4_u2^
3
copy4_u9 copy4_u3 copy4_u3
3
copy4_u5^ copy4_u3 nclk
3
copy4_u6 copy4_u9 nclk
3
copy4_u7 copy4_u5^ copy4_u8^
3
copy4_u8^ copy4_u7 copy4_u6
3
copy5_u1^ copy4_u7 clk^
3
copy5_u2^ copy4_u8^ clk^
3
copy5_u3 copy5_u1^ copy5_u4^
3
copy5_u4^ copy5_u3 copy5_u2^
3
copy5_u9 copy5_u3 copy5_u3
3
copy5_u5^ copy5_u3 nclk
3
copy5_u6 copy5_u9 nclk
3
copy5_u7 copy5_u5^ copy5_u8^
3
copy5_u8^ copy5_u7 copy5_u6
3
copy6_u1^ copy5_u7 clk^
3
copy6_u2^ copy5_u8^ clk^
3
copy6_u3 copy6_u1^ copy6_u4^
3
copy6_u4^ copy6_u3 copy6_u2^
3
copy6_u9 copy6_u3 copy6_u3
3
copy6_u5^ copy6_u3 nclk
3
copy6_u6 copy6_u9 nclk
3
copy6_u7 copy6_u5^ copy6_u8^
3
copy6_u8^ copy6_u7 copy6_u6
3
copy7_u1^ copy6_u7 clk^
3
copy7_u2^ copy6_u8^ clk^
3
copy7_u3 copy7_u1^ copy7_u4^
3
copy7_u4^ copy7_u3 copy7_u2^
3
copy7_u9 copy7_u3 copy7_u3
3
copy7_u5^ copy7_u3 nclk
3
copy7_u6 copy7_u9 nclk
3
copy7_u7 copy7_u5^ copy7_u8^
3
copy7_u8^ copy7_u7 copy7_u6
3
copy8_u1^ copy7_u7 clk^
3
copy8_u2^ copy7_u8^ clk^
3
copy8_u3 copy8_u1^ copy8_u4^
3
copy8_u4^ copy8_u3 copy8_u2^
3
copy8_u9 copy8_u3 copy8_u3
3
copy8_u5^ copy8_u3 nclk
3
copy8_u6 copy8_u9 nclk
3
copy8_u7 copy8_u5^ copy8_u8^
3
copy8_u8^ copy8_u7 copy8_u6
3
copy9_u1^ copy8_u7 clk^
3
copy9_u2^ copy8_u8^ clk^
3
copy9_u3 copy9_u1^ copy9_u4^
3
copy9_u4^ copy9_u3 copy9_u2^
3
copy9_u9 copy9_u3 copy9_u3
3
copy9_u5^ copy9_u3 nclk
3
copy9_u6 copy9_u9 nclk
3
copy9_u7 copy9_u5^ copy9_u8^
3
copy9_u8^ copy9_u7 copy9_u6
3
copy10_u1^ copy9_u7 clk^
3
copy10_u2^ copy9_u8^ clk^
3
copy10_u3 copy10_u1^ copy10_u4^
3
copy10_u4^ copy10_u3 copy10_u2^
3
copy10_u9 copy10_u3 copy10_u3
3
copy10_u5^ copy10_u3 nclk
3
copy10_u6 copy10_u9 nclk
3
copy10_u7 copy10_u5^ copy10_u8^
3
copy10_u8^ copy10_u7 copy10_u6
3
copy11_u1^ copy10_u7 clk^
3
copy11_u2^ copy10_u8^ clk^
3
copy11_u3 copy11_u1^ copy11_u4^
3
copy11_u4^ copy11_u3 copy11_u2^
3
copy11_u9 copy11_u3 copy11_u3
3
copy11_u5^ copy11_u3 nclk
3
copy11_u6 copy11_u9 nclk
3
copy11_u7 copy11_u5^ copy11_u8^
3
copy11_u8^ copy11_u7 copy11_u6
3
copy12_u1^ copy11_u7 clk^
3
copy12_u2^ copy11_u8^ clk^
3
copy12_u3 copy12_u1^ copy12_u4^
3
copy12_u4^ copy12_u3 copy12_u2^
3
copy12_u9 copy12_u3 copy12_u3
3
copy12_u5^ copy12_u3 nclk
3
copy12_u6 copy12_u9 nclk
3
copy12_u7 copy12_u5^ copy12_u8^
3
copy12_u8^ copy12_u7 copy12_u6
3
copy13_u1^ copy12_u7 clk^
3
copy13_u2^ copy12_u8^ clk^
3
copy13_u3 copy13_u1^ copy13_u4^
3
copy13_u4^ copy13_u3 copy13_u2^
3
copy13_u9 copy13_u3 copy13_u3
3
copy13_u5^ copy13_u3 nclk
3
copy13_u6 copy13_u9 nclk
3
copy13_u7 copy13_u5^ copy13_u8^
3
copy13_u8^ copy13_u7 copy13_u6
3
copy14_u1^ copy13_u7 clk^
3
copy14_u2^ copy13_u8^ clk^
3
copy14_u3 copy14_u1^ copy14_u4^
3
copy14_u4^ copy14_u3 copy14_u2^
3
copy14_u9 copy14_u3 copy14_u3
3
copy14_u5^ copy14_u3 nclk
3
copy14_u6 copy14_u9 nclk
3
copy14_u7 copy14_u5^ copy14_u8^
3
copy14_u8^ copy14_u7 copy14_u6
3
copy15_u1^ copy14_u7 clk^
3
copy15_u2^ copy14_u8^ clk^
3
copy15_u3 copy15_u1^ copy15_u4^
3
copy15_u4^ copy15_u3 copy15_u2^
3
copy15_u9 copy15_u3 copy15_u3
3
copy15_u5^ copy15_u3 nclk
3
copy15_u6 copy15_u9 nclk
3
copy15_u7 copy15_u5^ copy15_u8^
3
copy15_u8^ copy15_u7 copy15_u6
3
copy16_u1^ copy15_u7 clk^
3
copy16_u2^ copy15_u8^ clk^
3
copy16_u3 copy16_u1^ copy16_u4^
3
copy16_u4^ copy16_u3 copy16_u2^
3
copy16_u9 copy16_u3 copy16_u3
3
copy16_u5^ copy16_u3 nclk
3
copy16_u6 copy16_u9 nclk
3
copy16_u7 copy16_u5^ copy16_u8^
3
copy16_u8^ copy16_u7 copy16_u6
3
copy17_u1^ copy16_u7 clk^
3
copy17_u2^ copy16_u8^ clk^
3
copy17_u3 copy17_u1^ copy17_u4^
3
copy17_u4^ copy17_u3 copy17_u2^
3
copy17_u9 copy17_u3 copy17_u3
3
copy17_u5^ copy17_u3 nclk
3
copy17_u6 copy17_u9 nclk
3
copy17_u7 copy17_u5^ copy17_u8^
3
copy17_u8^ copy17_u7 copy17_u6
3
copy18_u1^ copy17_u7 clk^
3
copy18_u2^ copy17_u8^ clk^
3
copy18_u3 copy18_u1^ copy18_u4^
3
copy18_u4^ copy18_u3 copy18_u2^
3
copy18_u9 copy18_u3 copy18_u3
3
copy18_u5^ copy18_u3 nclk
3
copy18_u6 copy18_u9 nclk
3
copy18_u7 copy18_u5^ copy18_u8^
3
copy18_u8^ copy18_u7 copy18_u6
3
clk^ nclk nclk
3
nclk d4^ d4^
3
d4^ d3 d1
3
d3 d2^ d2^
3
d2^ d1 d1
3
d1 nC^ nC^
3
nC^ C C
3
data nA nA
3
nA A A
3
backdoor0^ copy0_u7 copy1_u7
3
backdoor1^ copy2_u7 copy3_u8^
3
backdoor2^ copy4_u8^ copy5_u8^
3
backdoor3^ copy6_u8^ copy7_u8^
3
backdoor4^ copy8_u7 copy9_u8^
3
backdoor5^ copy10_u8^ copy11_u7
3
backdoor6^ copy12_u8^ copy13_u8^
3
backdoor7^ copy14_u8^ copy15_u7
3
bd0' backdoor0^ backdoor0^
3
bd1' backdoor1^ backdoor1^
3
bd2' backdoor2^ backdoor2^
3
bd3' backdoor3^ backdoor3^
3
bd4' backdoor4^ backdoor4^
3
bd5' backdoor5^ backdoor5^
3
bd6' backdoor6^ backdoor6^
3
bd7' backdoor7^ backdoor7^
3
bd01^ bd0' bd1'
3
bd23^ bd2' bd3'
3
bd45^ bd4' bd5'
3
bd67^ bd6' bd7'
3
bd01' bd01^ bd01^
3
bd23' bd23^ bd23^
3
bd45' bd45^ bd45^
3
bd67' bd67^ bd67^
3
bd0123^ bd01' bd23'
3
bd4567^ bd45' bd67'
3
bd0123' bd0123^ bd0123^
3
bd4567' bd4567^ bd4567^
3
bdall^ bd0123' bd4567'
3
bdall' bdall^ bdall^
3
bdff_u1^ bdall' clk^
3
bdff_u2^ bdall^ clk^
3
bdff_u3 bdff_u1^ bdff_u4^
3
bdff_u4^ bdff_u3 bdff_u3
3
bdff_u9 bdff_u3 bdff_u3
3
bdff_u5^ bdff_u3 nclk
3
bdff_u6 bdff_u9 nclk
3
triggered bdff_u5^ bdff_u8^
3
bdff_u8^ triggered bdff_u6
3
Cout_tentative' t9 t9
3
At A triggered
3
Cout Cout_tentative' At
3
S' S_tentative At
3
S S' S'
4
}
=
=
=
}
=
=
}
=
=
=
=
=
}
}
}
A
B
C
D
A
B
C
D
A
B
C
D
A
B
C
D
A
B
C
D
A
B
C
D
A
B
C
D
A
B
C
D
X
=

5
""")

flag = ''
output = r.recvall()
print("Out:", output)
for line in output.splitlines():
  if line.startswith(b'CPU outputs: '):
    flag += chr(line.strip()[-1])

print(flag)
assert flag.startswith('CTF{H4rdwar3_acc3ler4ted_backd00rs_are_7he_w0rst}')

exit(0)
