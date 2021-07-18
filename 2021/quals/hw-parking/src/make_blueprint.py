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

# name x y rot flip
def up(r, x, y):
    r.append("straight %d %d 0 0" % (x, y))
def right(r, x, y):
    r.append("straight %d %d 1 0" % (x, y))
def down(r, x, y):
    r.append("straight %d %d 2 0" % (x, y))
def left(r, x, y):
    r.append("straight %d %d 3 0" % (x, y))

def orgate_up(r, x, y):
    r.append("or %d %d 2 0" % (x, y))
def orgate_right(r, x, y):
    r.append("or %d %d 3 0" % (x, y))
def orgate_down(r, x, y):
    r.append("or %d %d 0 0" % (x, y))
def orgate_left(r, x, y):
    r.append("or %d %d 1 0" % (x, y))

def andgate_up(r, x, y):
    r.append("and %d %d 2 0" % (x, y))
def andgate_right(r, x, y):
    r.append("and %d %d 3 0" % (x, y))
def andgate_down(r, x, y):
    r.append("and %d %d 0 0" % (x, y))
def andgate_left(r, x, y):
    r.append("and %d %d 1 0" % (x, y))

def down_to_right(r, x, y):
    r.append("turn %d %d 0 0" % (x, y))
def left_to_down(r, x, y):
    r.append("turn %d %d 1 0" % (x, y))
def up_to_left(r, x, y):
    r.append("turn %d %d 2 0" % (x, y))
def right_to_up(r, x, y):
    r.append("turn %d %d 3 0" % (x, y))

def right_to_down(r, x, y):
    r.append("turn %d %d 0 1" % (x, y))
def down_to_left(r, x, y):
    r.append("turn %d %d 1 1" % (x, y))
def left_to_up(r, x, y):
    r.append("turn %d %d 2 1" % (x, y))
def up_to_right(r, x, y):
    r.append("turn %d %d 3 1" % (x, y))

def split_down_to_left(r, x, y):
    r.append("split %d %d 0 0" % (x, y))
def split_left_to_up(r, x, y):
    r.append("split %d %d 1 0" % (x, y))
def split_up_to_right(r, x, y):
    r.append("split %d %d 2 0" % (x, y))
def split_right_to_down(r, x, y):
    r.append("split %d %d 3 0" % (x, y))

def split_right_to_up(r, x, y):
    r.append("split %d %d 0 1" % (x, y))
def split_down_to_right(r, x, y):
    r.append("split %d %d 1 1" % (x, y))
def split_left_to_down(r, x, y):
    r.append("split %d %d 2 1" % (x, y))
def split_up_to_left(r, x, y):
    r.append("split %d %d 3 1" % (x, y))

def cross_up_right(r, x, y):
    r.append("crossover %d %d 0 0" % (x, y))
def cross_down_right(r, x, y):
    r.append("crossover %d %d 1 0" % (x, y))
def cross_down_left(r, x, y):
    r.append("crossover %d %d 2 0" % (x, y))
def cross_up_left(r, x, y):
    r.append("crossover %d %d 3 0" % (x, y))

def input_right(r, x, y):
    r.append("input %d %d 0 0" % (x, y))
def input_down(r, x, y):
    r.append("input %d %d 1 0" % (x, y))
def output_right(r, x, y):
    r.append("output %d %d 0 0" % (x, y))
def output_up(r, x, y):
    r.append("output %d %d 3 0" % (x, y))
def output_down(r, x, y):
    r.append("output %d %d 1 0" % (x, y))
def zero_up(r, x, y):
    r.append("zero %d %d 0 0" % (x, y))
def one_up(r, x, y):
    r.append("one %d %d 0 0" % (x, y))
def zero_right(r, x, y):
    r.append("zero %d %d 1 0" % (x, y))
def one_right(r, x, y):
    r.append("one %d %d 1 0" % (x, y))
def zero_down(r, x, y):
    r.append("zero %d %d 2 0" % (x, y))
def one_down(r, x, y):
    r.append("one %d %d 2 0" % (x, y))

def prep2x2(r, x, y):
    down_to_right(r, x+0, y+0)
    left_to_up   (r, x+0, y+1)
    left_to_down (r, x+0, y+3)
    down(r, x+0, y+4)
    down(r, x+0, y+5)
    split_up_to_right(r, x+0, y+6)
    down(r, x+0, y+7)
    down(r, x+0, y+8)
    down(r, x+0, y+9)
    up_to_right(r, x+0, y+10)
    left_to_down(r, x+0, y+11)
    up_to_right(r, x+0, y+12)
    right(r, x+0, y+13)

    right(r, x+1, y+0)
    cross_up_right(r, x+1, y+6)
    cross_up_right(r, x+1, y+10)
    right(r, x+1, y+12)
    right(r, x+1, y+13)

    right(r, x+2, y+0)
    down_to_right(r, x+2, y+2)
    up(r, x+2, y+3)
    up(r, x+2, y+4)
    up(r, x+2, y+5)
    split_down_to_right(r, x+2, y+8)
    up(r, x+2, y+9)
    left_to_up(r, x+2, y+12)
    right(r, x+2, y+13)

    right(r, x+3, y+0)
    cross_down_right(r, x+3, y+1)
    cross_up_right(r, x+3, y+6)
    cross_up_right(r, x+3, y+8)
    cross_up_right(r, x+3, y+10)
    down_to_right(r, x+3, y+12)
    left_to_up(r, x+3, y+13)

    split_left_to_down(r, x+4, y+0)
    up_to_right(r, x+4, y+3)
    down_to_right(r, x+4, y+5)
    split_left_to_up(r, x+4, y+12)

    left_to_down(r, x+5, y+0)
    andgate_right(r, x+5, y+1)
    left_to_up(r, x+5, y+2)
    left_to_down(r, x+5, y+3)
    andgate_right(r, x+5, y+4)
    left_to_up(r, x+5, y+5)
    left_to_down(r, x+5, y+6)
    andgate_right(r, x+5, y+7)
    left_to_up(r, x+5, y+8)
    left_to_down(r, x+5, y+10)
    andgate_right(r, x+5, y+11)
    left_to_up(r, x+5, y+12)

def make_half_adder(r, x, y):
    prep2x2(r, x, y)
    right(r, x+6, y+1)
    split_left_to_down(r, x+6, y+4)
    orgate_right(r, x+6, y+5)
    up(r, x+6, y+6)
    split_left_to_up(r, x+6, y+7)
    right(r, x+6, y+11)

    split_left_to_down(r, x+7, y+1)
    down(r, x+7, y+2)
    orgate_right(r, x+7, y+3)
    left_to_up(r, x+7, y+4)
    right(r, x+7, y+5)
    right(r, x+7, y+7)
    right(r, x+7, y+11)

    right(r, x+8, y+1)
    right(r, x+8, y+3)
    cross_down_right(r, x+8, y+4)
    right(r, x+8, y+7)
    right(r, x+8, y+11)

    right(r, x+9, y+1)
    left_to_down(r, x+9, y+3)
    orgate_right(r, x+9, y+6)
    left_to_up(r, x+9, y+7)
    right(r, x+9, y+11)

    right(r, x+10, y+1)
    down_to_right(r, x+10, y+3)
    up(r, x+10, y+4)
    left_to_up(r, x+10, y+5)
    cross_up_right(r, x+10, y+6)
    right(r, x+10, y+11)

    down_to_right(r, x+11, y+0)
    left_to_up(r, x+11, y+1)
    cross_up_right(r, x+11, y+3)
    down_to_right(r, x+11, y+5)
    up(r, x+11, y+8)
    up(r, x+11, y+9)
    up(r, x+11, y+10)
    split_left_to_up(r, x+11, y+11)

    left_to_down(r, x+12, y+0)
    orgate_right(r, x+12, y+1)
    up(r, x+12, y+2)
    left_to_up(r, x+12, y+5)
    left_to_down(r, x+12, y+6)
    down(r, x+12, y+7)
    down(r, x+12, y+8)
    up_to_right(r, x+12, y+9)
    right(r, x+12, y+11)

def make_full_adder(r, x, y):
    make_half_adder(r, x, y+1)
    make_half_adder(r, x+17, y+1)
    up_to_right(r, x+13, y+0)
    left_to_down(r, x+14, y+0)
    up_to_right(r, x+15, y+0)
    left_to_down(r, x+16, y+0)
    cross_down_right(r, x+13, y+1)
    cross_down_right(r, x+15, y+1)
    cross_down_right(r, x+13, y+3)
    cross_down_right(r, x+15, y+3)

    up_to_right(r, x+14, y+5)
    left_to_down(r, x+15, y+5)
    for i in range(7):
        down(r, x+16, y+5+i)
        down(r, x+15, y+6+i)
    down(r, x+15, y+13)
    up_to_right(r, x+16, y+12)
    up_to_right(r, x+15, y+14)
    right(r, x+16, y+14)

    right(r, x+13, y+10)
    left_to_down(r, x+14, y+10)
    left_to_down(r, x+13, y+12)
    down(r, x+13, y+13)
    down(r, x+13, y+14)
    down(r, x+14, y+11)
    down(r, x+14, y+12)
    down(r, x+14, y+13)
    down(r, x+14, y+14)

    up_to_left(r, x+13, y+15)
    right_to_down(r, x+12, y+15)
    up_to_right(r, x+12, y+16)
    orgate_down(r, x+13, y+16)
    down(r, x+13, y+17)
    cross_down_left(r, x+14, y+15)
    up_to_right(r, x+14, y+17)
    andgate_down(r, x+15, y+17)
    left(r, x+16, y+17)
    right_to_down(r, x+16, y+15)
    up_to_left(r, x+16, y+16)

    for i in range(13):
        left(r, x+17+i, y+15)
        left(r, x+17+i, y+17)

    left(r, x+30, y+17)
    up_to_left(r, x+31, y+17)
    up_to_left(r, x+30, y+15)
    for i in range(6):
        down(r, x+31, y+16-i)
    left_to_down(r, x+30, y+12)
    left_to_down(r, x+31, y+10)
    down(r, x+30, y+13)
    down(r, x+30, y+14)
    right(r, x+30, y+10)

    right(r, x+30, y+2)
    right(r, x+31, y+2)
    right(r, x+30, y+4)
    right(r, x+31, y+4)

def make_n_bit_adder(r, x, y, n):
    for i in range(n):
        make_full_adder(r, x, y+i*18)
    zero_down(r, x+13, y-1)
    one_down(r, x+15, y-1)

def make_xor(r, x, y):
    prep2x2(r, x, y)
    right(r, x+6, y+1)
    right(r, x+7, y+1)
    left_to_down(r, x+6, y+4)
    left_to_down(r, x+8, y+1)
    down(r, x+8, y+2)
    orgate_right(r, x+8, y+3)
    orgate_right(r, x+6, y+5)
    left_to_up(r, x+6, y+7)
    up(r, x+6, y+6)
    cross_up_right(r, x+7, y+5)
    up(r, x+8, y+4)
    right(r, x+6, y+11)
    right(r, x+7, y+11)
    left_to_up(r, x+8, y+11)
    up(r, x+8, y+10)
    up(r, x+8, y+9)
    up(r, x+8, y+8)
    up(r, x+8, y+7)

def make_n_bit_xor(r, x, y, n):
    for i in range(n):
        make_xor(r, x, y+i*18)

def make_n_bit_const(r, x, y, n, const):
    for i in range(n):
        if const & (1<<i):
            zero_right(r, x, y + 18*i)
            one_right(r, x, y + 2 + 18*i)
        else:
            one_right(r, x, y + 18*i)
            zero_right(r, x, y + 2 + 18*i)

def make_assert_0(r, x, y, n):
    for i in range(n):
        andgate_down(r, x+1, y+5 + i*18)
        right(r, x, y+5 + i*18)
        up_to_left(r, x+2, y+5 + i*18)
        up_to_right(r, x+1, y+6 + i*18)
        left_to_down(r, x+2, y+6 + i*18)
        for j in range(8):
            down(r, x+2, y+7 + j + i*18)
        for j in range(8):
            down(r, x+2, y+4 - j + i*18)
    one_down(r, x+2, y-4)
    up_to_right(r, x+2, y+15+(n-1)*18)
    output_right(r, x+3, y+15+(n-1)*18)


def main():
    res = []

    if 0: # AND test
        input_right(res, 0, 1)
        down_to_right(res, 0, 0)
        left_to_down(res, 1, 0)
        andgate_right(res, 1, 1)
        input_right(res, 1, 2)
        output_right(res, 2, 1)
    if 0: # OR test
        input_right(res, 0, 1)
        down_to_right(res, 0, 0)
        left_to_down(res, 1, 0)
        orgate_right(res, 1, 1)
        input_right(res, 1, 2)
        output_right(res, 2, 1)
    if 0: # split test
        input_right(res, 0, 1)
        split_down_to_right(res, 0, 0)
        left_to_down(res, 1, 0)
        andgate_right(res, 1, 1)
        split_down_to_right(res, 1, 2)
        input_right(res, 1, 3)
        output_right(res, 2, 1)

    if 0: # Crossover test
        input_right(res, 0, 3)
        down_to_right(res, 0, 2)
        cross_up_right(res, 1, 2)
        input_right(res, 2, 4)
        up(res, 2, 1)
        down_to_right(res, 2, 0)
        left_to_down(res, 3, 0)
        andgate_right(res, 3, 1)
        left_to_up(res, 3, 2)
        output_right(res, 4, 1)

    if 0: # Xor
        down_to_right(res, 0, 1)
        input_right(res, 0, 2)
        up_to_right(res, 0, 3)
        down_to_right(res, 0, 11)
        input_right(res, 0, 12)
        up_to_right(res, 0, 13)
        make_xor(res, 1, 0)
        make_n_bit_xor(res, 1, 0, 1)
        if 0: # Xor
            output_right(res, 10, 5)
        if 0: # Xornot
            output_right(res, 10, 3)

    if 0: # Full adder.
        right_to_down(res, 14, 0)
        input_down(res, 15, 0)
        left_to_down(res, 16, 0)
        down_to_right(res, 0, 3)
        input_right(res, 0, 4)
        up_to_right(res, 0, 5)
        down_to_right(res, 0, 13)
        input_right(res, 0, 14)
        up_to_right(res, 0, 15)
        make_n_bit_adder(res, 1, 1, 1)
        if 0: # Sum
            output_right(res, 33, 5)
        if 0: # Sumnot
            output_right(res, 33, 3)
        if 0: # Cout
            output_down(res, 14, 19)
        if 0: # Cnot
            output_down(res, 16, 19)

    if 1: # The full thing
        CONST_A = 0
        for i in range(100):
            CONST_A |= 0xdeadc0de << (32 * i)
        CONST_B = 0
        for i in range(100):
            CONST_B |= 0x13371337 << (32 * i)
        #FLAG = "CTF{4t_leas7_1t_h4d_on3_fl0or}"
        FLAG = "2TheBr1m"
        BITS = 8 * len(FLAG)
        flagbits = 0
        for i, c in enumerate(FLAG):
            c = ord(c)
            for j in range(8):
                bit = (c >> j) & 1
                flagbits |= bit << (i*8+j)

        MASK = (1<<BITS) - 1
        x = (flagbits ^ CONST_A) & MASK
        x = (x * 3) & MASK
        x = (x ^ (x>>1)) & MASK
        x = ((x>>1) | (x<<(BITS-1))) & MASK
        x  = (x + CONST_B) & MASK
        FLAG_CONST = x


        for kk in range(1):
            # 1. Inputs
            for i in range(BITS):
                down_to_right(res, 0, 23 + 18*i)
                input_right(res, 0, 24 + 18*i)
                up_to_right(res, 0, 25 + 18*i)

            # 2. Xor with 0xdeadbeef
            make_n_bit_const(res, 0, 33, BITS, CONST_A)
            make_n_bit_xor(res, 1, 22, BITS)

            def make_n_bit_check(res, x, y, n, what):
                make_n_bit_const(res, x-10+10, y-20+35, n, what)
                make_n_bit_xor(res, x-10+11, y-20+24, n)
                make_assert_0(res, x-10+20, y-20+22, n)
                for i in range(n):
                    right(res, x-10+10, y-20+25 + i*18)
                    right(res, x-10+10, y-20+27 + i*18)

            if 0:
                make_n_bit_check(res, 10, 20, BITS, 0)
                break

            # 3. Multiply by 3
            zero_down(res, 11, 9)
            one_down(res, 13, 9)
            for i in range(BITS):
                right(res, 10, 25+18*i)
                split_left_to_down(res, 13, 25+18*i)
                cross_down_right(res, 12, 26+18*i)
                right(res, 10, 27+18*i)
                right(res, 12, 25+18*i)
                right(res, 11, 25+18*i)
                split_left_to_down(res, 11, 27+18*i)
                down(res, 11, 28+18*i-18)
                down(res, 11, 29+18*i-18)
                down(res, 11, 30+18*i-18)
                down(res, 11, 31+18*i-18)
                down(res, 11, 32+18*i-18)
                down(res, 11, 33+18*i-18)
                down(res, 11, 34+18*i-18)
                up_to_right(res, 11, 35+18*i-18)
                right(res, 12, 35+18*i-18)
                right(res, 13, 35+18*i-18)
                down(res, 13, 28+18*i-18)
                down(res, 13, 29+18*i-18)
                down(res, 13, 30+18*i-18)
                down(res, 13, 31+18*i-18)
                down(res, 13, 32+18*i-18)
                up_to_right(res, 13, 33+18*i-18)

            make_n_bit_adder(res, 14, 13, BITS)

            if 0:
                make_n_bit_check(res, 46, 10, BITS, 2)
                break

            # 4. x ^= x<<1
            make_n_bit_xor(res, 49, 22, BITS)

            for i in range(BITS):
                right(res, 46, 15 + 18*i)
                right(res, 47, 15 + 18*i)
                split_left_to_down(res, 48, 15 + 18*i)
                split_left_to_down(res, 46, 17 + 18*i)
                cross_down_right(res, 47, 16 + 18*i)

                down(res, 46, 18+18*i)
                down(res, 46, 19+18*i)
                down(res, 46, 20+18*i)
                down(res, 46, 21+18*i)
                down(res, 46, 22+18*i)
                down(res, 46, 23+18*i)
                down(res, 46, 24+18*i)
                up_to_right(res, 46, 25+18*i)
                right(res, 47, 25+18*i)
                right(res, 48, 25+18*i)

                down(res, 48, 18+18*i)
                down(res, 48, 19+18*i)
                down(res, 48, 20+18*i)
                down(res, 48, 21+18*i)
                down(res, 48, 22+18*i)
                up_to_right(res, 48, 23+18*i)

            one_right(res, 48, 18*BITS + 15)
            zero_right(res, 48, 18*BITS + 17)

            if 0:
                make_n_bit_check(res, 58, 20, BITS, 2)
                break

            # 5. Rotate by 1

            right(res, 58, 25)
            right(res, 58, 27)
            left_to_down(res, 59, 27)
            right(res, 59, 25)
            right(res, 60, 25)
            left_to_down(res, 61, 25)
            down(res, 61, 26)
            down(res, 61, 27)
            for j in range(14):
                down(res, 59, 28+j)
                down(res, 61, 28+j)
            up_to_right(res, 61, 43 + 18*BITS - 18)
            down(res, 61, 42 + 18*BITS - 18)
            down(res, 59, 42 + 18*BITS - 18)
            down(res, 59, 43 + 18*BITS - 18)
            down(res, 59, 44 + 18*BITS - 18)
            up_to_right(res, 59, 45 + 18*BITS - 18)
            right(res, 60, 45 + 18*BITS - 18)
            right(res, 61, 45 + 18*BITS - 18)

            for i in range(1, BITS):
                cross_down_right(res, 58, 24+18*i)
                cross_down_right(res, 60, 24+18*i)
                cross_down_right(res, 58, 26+18*i)
                cross_down_right(res, 60, 26+18*i)
                for j in range(14):
                    down(res, 59, 28+18*i+j)
                    down(res, 61, 28+18*i+j)

            #make_assert_0(res, 62, 38, BITS)

            # 6. Add 0x1337...

            make_n_bit_adder(res, 63, 41, BITS)
            for i in range(BITS):
                right(res, 62, 43 + 18*i)
                right(res, 62, 45 + 18*i)
            make_n_bit_const(res, 62, 53, BITS, CONST_B)

            # make_assert_0(res, 95, 38, BITS)
            # break

            # 7. Xor with flagconst

            make_n_bit_const(res, 95, 33, BITS, FLAG_CONST)
            make_n_bit_xor(res, 96, 32, BITS)
            for i in range(BITS):
                right(res, 95, 43 + i*18)
                right(res, 95, 45 + i*18)

            make_assert_0(res, 105, 30, BITS)


        with open("/tmp/fc", "w") as f:
            f.write(str(FLAG_CONST) + "\n")
        if 0:
            with open("/tmp/bruted", "w") as f:
                f.write(hex(FLAG_CONST) + "\n")
                for flag in range(1<<BITS):
                    x = (flag ^ CONST_A) & MASK
                    x = (x * 3) & MASK
                    x = (x ^ (x>>1)) & MASK
                    x = ((x>>1) | (x<<(BITS-1))) & MASK
                    x  = (x + CONST_B) & MASK
                    x = (x ^ FLAG_CONST) & MASK
                    if x == 0:
                        f.write(str(flag) + "\n")


    print("\n".join(res))

main()
