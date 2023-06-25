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

rom = bytes(0x100) + open('auxin.rom','rb').read()
WIDTH = 17
HEIGHT = 19

puzzle = ['.']*(WIDTH*HEIGHT)
givens = rom[0x77ef:0x7927]
for i in range(0, len(givens), 2):
    given = int(givens[i:i+2].hex(), 16)
    digit = given % 10
    pos = given // 10
    puzzle[pos] = str(digit)

print('puzzle:')
for i in range(HEIGHT):
    print(''.join(puzzle[i*WIDTH:(i+1)*WIDTH]))
print()

# now use your favorite fillomino solver to get the solution...
# (e.g. https://github.com/obijywk/grilops/blob/master/examples/fillomino.py)

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

magic_xor = rom[0x7d85:0x7d85+0x80]
magic_mult = rom[0x7e05:0x7e05+0x80]
magic_final_xor = rom[0x7e85:0x7e85+0x80]

solution = int(''.join(str(int(i)-1) for i in solution[::-1]), 9)
x = bytes.fromhex(f'{solution:0256x}')
x = bytes(i^j for i,j in zip(x, magic_final_xor))
x = int(x[::-1].hex(), 16)

modulus = 1 << 1024
x = (x * pow(int(magic_mult[::-1].hex(), 16), -1, modulus)) % modulus
x = bytes.fromhex(f'{x:0256x}')[::-1]
x = bytes(i^j for i,j in zip(x, magic_xor))
x = x.rstrip(b'\x00')

print(x.decode('ascii'))
