# Copyright 2023 Google LLC
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

import random

puzzle = ''.join('''
6..6.7...121.2...
2..6772.38......2
54.27754..443..3.
.5..75..28.4..45.
5..82.541.1....1.
..........5.6..65
...3155.1..7...62
.852..5.68....76.
....33.23134.56..
15....44...525.55
3.55425.12.888..3
4...3.......8..8.
.453...3.4.1.3212
.771..599.163...4
..7.2..9.46.....6
77...4.1..2.1....
2..344....265.661
6..6716.994.21244
7.....13.....3.4.
'''.split())

solution = ''.join('''
66667723312122432
22667724382336432
54427754284436435
55427554284456455
55482554181556715
88882666885566765
83331556183777762
88525556683444762
55523322313425666
15444344335525555
33554254125888333
43553254325888882
44533553345133212
47712659941635244
77732669946665446
77634461942615666
22634463992655661
66667163994221244
77777713444333244
'''.split())

magic_xor = '''
    3e22 04b7 7d6a 8e19 1d7b d489 9c6c 8a81
    af92 c533 291d 9196 80c9 d2fd 0818 eddc
    4d4b 1d13 d82b 9be6 95b6 c3e2 25e2 9d05
    a52d bcad 31d9 0e90 f878 9072 64a7 7fde
    dda4 8f60 6ee0 ec74 048f d72d 817d 7d62
    12e1 ca69 8641 67a3 d540 252b d758 ce65
    8c88 c785 1654 72d3 4b49 065c ccbe bd83
    a9f1 61ad 4b09 f572 0f76 6fff 8072 5911
'''

magic_mult = '''
    9978 bd25 e95f 02ec 13cc 6438 d14e deb6
    c7e3 fac5 94b4 21ca 57b7 d102 ff6c a71d
    a633 cc88 0e5d e39f 9d5a ca7d 830f ec73
    240a 8250 346f 6e49 b496 60f7 4d52 2eb0
    d38c 2ed2 51dd 0720 6851 e71a 465e 59d2
    ed75 f5da 88aa 4f40 ecda 86b6 032d 8e0f
    f79a 0acb 7d2c 1cfe 301a f5d3 e225 dcc1
    486f 3935 4ee9 cbb6 8779 5bef 5234 e8e3
'''

flag = b'CTF{C0m3_5Tay_4_Wh1Le_anD_l1S7eN_T0_tH3_Mus1C___}'
flag += bytes(0x80-len(flag))
magic_xor = bytes.fromhex(magic_xor)

x = bytes(i^j for i,j in zip(flag, magic_xor))

x = int(x[::-1].hex(), 16)
magic_mult = int(bytes.fromhex(magic_mult)[::-1].hex(), 16)

x = (x * magic_mult) & ((1 << 1024) - 1)
x = bytes.fromhex(f'{x:0256x}')[::-1]

solution = int(''.join(str(int(i)-1) for i in solution[::-1]), 9)
y = bytes.fromhex(f'{solution:0256x}')

magic_final_xor = bytes(i^j for i,j in zip(x, y))

print('@magic_final_xor', end='')
for i in range(len(magic_final_xor)):
    if i%16 == 0:
        print('\n    ', end='')
    elif i%2 == 0:
        print(' ', end='')
    print(f'{magic_final_xor[i]:02x}', end='')
print()


l = []
for i in range(len(puzzle)):
    if puzzle[i] != '.':
        l.append('{:04x}'.format(i*10 + int(puzzle[i])))
random.shuffle(l)
print('@givens')
for i in range(0, len(l), 8):
    print('    '+' '.join(l[i:i+8]))
print('@givens_end')
