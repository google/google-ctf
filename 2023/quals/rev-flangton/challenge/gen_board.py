# Copyright 2023 Google LLC
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

import sys
import random
import json
from collections import defaultdict

random.seed(1337)

def put_a(top, left):
    board[top,left] = 1
    board[top,left+1] = 1
    board[top+1,left] = 1

def put_b(top, left):
    board[top, left] = 1
    board[top, left+2] = 1
    board[top+1, left+1] = 1
    board[top+1, left+3] = 1
    board[top+2, left] = 1
    board[top+2, left+3] = 1
    board[top+2, left+4] = 1

def put_c(top, left):
    board[top, left] = 1
    board[top, left+2] = 1
    board[top, left+3] = 1
    board[top, left+4] = 1
    board[top+1, left+1] = 1
    board[top+1, left+3] = 1
    board[top+2, left+4] = 1
    board[top+3, left+1] = 1
    board[top+3, left+2] = 1
    board[top+4, left] = 1
    board[top+4, left+1] = 1
    board[top+4, left+3] = 1

def put_j(top, left):
    board[top,left] = 1
    board[top,left+1] = 1
    board[top+1,left+2] = 1
    board[top+2,left] = 1
    board[top+2,left+2] = 1

def horiz(top, left, n):
    for i in range(n):
        board[top, left+i] = 1

def vert(top, left, n):
    for i in range(n):
        board[top+i, left] = 1

def put_detector(top, left):
    # Input at top-1, left+3
    # Ant enters through top+1, left+1 facing up.
    horiz(top, left, 4)
    horiz(top+1, left+1, 3)
    board[top+2, left+5] = 1

def put_one(top, left):
    horiz(top, left, 2)

# Finished.
def put_NOT(top, left):
    # Input  at top, left+6
    # Output at top+32, left+6
    # Ant enters through top+5, left facing right.
    # Ant exits  through top+5, left+14 facing right.
    horiz(top + 5, left, 2)
    put_a(top + 3, left + 2)
    put_detector(top + 1, left + 3)
    board[top + 2, left + 2] = 1
    put_j(top + 3, left + 9)
    horiz(top + 6, left + 11, 2)
    board[top + 5, left + 13] = 1
    board[top + 5, left + 4] = 1
    horiz(top + 6, left + 5, 4)
    horiz(top + 7, left + 6, 2)

    # Extend to 32.
    vert(top + 8, left + 6, 32-8)
    vert(top + 8, left + 7, 32-8)
    horiz(top + 5, left + 14, 28-14) # Extend right.

    put_extender(top, left)

def put_pattern(top, left, pattern):
    for i, line in enumerate(pattern):
        for j, c in enumerate(line):
            if c == '#':
                board[top+i, left+j] = 1

# Finished.
# Now modifying...
def put_AND(top, left):
    # Input  at top, left+6 and top, left+34
    # Output at top+32, left+6
    # Ant enters through top+5, left facing right.
    # Ant exits  through top+5, left+26 facing right.

    # NOT 1
    horiz(top + 5, left, 2)
    put_a(top + 3, left + 2)
    put_detector(top + 1, left + 3)
    board[top + 2, left + 2] = 1

    put_b(top + 7, left + 4)
    vert(top + 5, left + 4, 2)
    # NOT 2
    horiz(top + 4, left + 9, 21)
    put_a(top + 3, left + 30)
    put_detector(top + 1, left + 31)
    board[top + 2, left + 30] = 1

    put_pattern(top + 3, left + 34, [
        "  #",
        "  #",
        " # ",
        "#  "])

    put_b(top + 7, left + 32)
    vert(top + 5, left + 32, 2)

    put_j(top + 9, left + 37)
    board[top + 12, left + 39] = 1
    put_j(top + 12, left + 40)
    put_pattern(top + 6, left + 6, [
        "####  ",
        "   #  ",
        "   #  ",
        "    ##",
        "   #  ",
        "    # "])
    horiz(top + 9, left + 12, 20)
    horiz(top + 12, left + 11, 26)
    board[top + 15, left + 42] = 1
    vert(top + 5, left + 43, 11)
    horiz(top + 5, left + 43, 3)
    board[top + 6, left + 44] = 1

    vert(top + 9, left + 3, 6)
    horiz(top + 15, left + 4, 36)
    horiz(top + 16, left + 5, 4)
    horiz(top + 17, left + 6, 2)

    # Extend to 32
    vert(top + 18, left + 6, 14)
    vert(top + 18, left + 7, 14)
    horiz(top + 5, left + 46, 56-46) # Extend right.

    put_extender(top, left)
    horiz(top + 43, left + 28, 28)

# Finished
def put_CROSS(top, left):
    # Input  at top, left+6 and top, left+34
    # Output at top+32, left+6 and top+32, left+34
    # Ant enters through top+5, left facing right.
    # Ant exits  through top+5, left+48 facing right.

    # NOT 1
    for i in range(2):
        i *= 28
        horiz(top + 5, left+i, 2)
        put_a(top + 3, left+i + 2)
        put_detector(top + 1, left+i + 3)
        board[top + 2, left+i + 2] = 1

        put_pattern(top + 3, left+i + 4, [
            "    #",
            "    #",
            "#  # ",
            " # #    ###",
            " # #   #",
            "      #",
            "       ",
            "       ",
            "      #",
            "       #",
            "       #",
            "      #",
            ])

        put_c(top + 8, left+i + 5)

    put_pattern(top + 15, left + 9, [
        " #",
        " #   #####",
        " #  #",
        " # #",
        "# #"
        ])


    put_pattern(top + 20, left + 14, [
        "           #####  #",
        "         ##    #  #",
        "        #  #  ##  #",
        "#      # ## ##    #",
        " #    # #  #  #   #",
        "  #  # #   # # #  #", # bottom C top here
        "   # ##  # ##  ####",
        "    ##  #  ##",
        "      # ## # #",
        "     #   #  # #######",
        "#####        ####### #"
        ])
    horiz(top + 31, left + 34, 2)

    # Right under C
    put_pattern(top + 13, left + 33, [
        "",
        "#####",
        "    #",
        "   #",
        "  #",
        " #",
        "#",
        ])
    # Rightmost part
    put_pattern(top + 5, left + 38, [
        "     ##  #",
        "  ###  ##",
        " #   # ##",
        "#   #  ##",
        "   #",
        "   #",
        "#  #",
        " # #",
        " # #",
        "# #",
        "##"
        ])
    # Middle part
    put_pattern(top + 5, left + 15, [
        "      ##  ###", # J
        "######  ##",    # J
        "      # ##",    # J
        "     #  ##",
        "    #",
        "   #",
        "  #",
        "  #  # ##", # C
        "   #  ## ",
        "    #      #######",
        "     # #  #",
        "####### ##", # C end
        "       #",
        "        #",
        "         #"
        ])

    # Bottom left
    put_b(top + 20, left + 9)
    put_pattern(top + 22, left + 6, [
        "  #",
        "  #",
        "  #",
        "  #",
        "  #",
        "  #",
        "  #",
        " #",
        "# ######",
        "##"
        ])
    horiz(top + 5, left + 48, 56-48) # Extend right.

    put_extender(top, left)
    put_extender(top, left + 28)

# Finished.
def put_PASS(top, left):
    # Input  at top, left+6
    # Output at top+32, left+6
    # Ant enters through top+5, left facing right.
    # Ant exits  through top+5, left+56 facing right.
    horiz(top + 5, left, 2)
    put_a(top + 3, left + 2)
    put_detector(top + 1, left + 3)

    put_b(top + 7, left + 4)
    vert(top + 5, left + 4, 2)
    board[top + 6, left + 6] = 1
    board[top + 5, left + 7] = 1
    board[top + 4, left + 8] = 1
    board[top + 2, left + 2] = 1
    vert(top + 9, left + 3, 4)
    horiz(top + 12, left + 3, 6)

    put_j(top + 9, left + 9)
    board[top + 12, left + 11] = 1
    vert(top + 5, left + 12, 8)

    vert(top + 13, left + 6, 32-13)
    vert(top + 13, left + 7, 32-13)
    horiz(top + 5, left + 13, 28-13)

    put_extender(top, left)

# Finished.
def put_SPLIT(top, left):
    # Input  at top, left+6
    # Output at top+32, left+6 and top+32, left+34
    # Ant enters through top+5, left facing right.
    # Ant exits  through top+5, left+56 facing right.
    horiz(top + 5, left, 2)
    put_a(top + 3, left + 2)
    put_detector(top + 1, left + 3)

    put_b(top + 7, left + 4)
    vert(top + 5, left + 4, 2)
    board[top + 6, left + 6] = 1
    board[top + 5, left + 7] = 1
    board[top + 4, left + 8] = 1
    board[top + 2, left + 2] = 1
    vert(top + 9, left + 3, 4)
    horiz(top + 12, left + 3, 6)

    put_j(top + 9, left + 9)
    board[top + 12, left + 11] = 1
    vert(top + 5, left + 12, 8)

    horiz(top + 29, left + 8, 26)
    horiz(top + 30, left + 8, 26)
    vert(top + 28, left + 34, 4)
    vert(top + 28, left + 35, 4)

    vert(top + 13, left + 6, 32-13)
    vert(top + 13, left + 7, 32-13)
    horiz(top + 5, left + 13, 56-13)

    put_extender(top, left)
    put_extender(top, left + 28)

# Finished.
def put_ZERO(top, left):
    horiz(top + 5, left, 28)
    horiz(top + 43, left, 28)

# Finished.
def put_ONE(top, left):
    # Output at top+32, left+6
    horiz(top + 5, left, 28)
    horiz(top + 6, left + 5, 4)
    vert(top + 6, left + 6, 32-6)
    vert(top + 6, left + 7, 32-6)

    put_extender(top, left)

def put_right_edge(top, left):
    horiz(top + 5, left, 3)
    vert(top + 5, left + 3, 38)
    horiz(top + 43, left, 3)
    board[top + 42, left + 2] = 1

def put_extender(top, left):
    put_pattern(top + 32, left + 6, [
        "##",
        "###",
        "############## ",
        "#####         # ",
        "     #        #",
        "     #        #",
        "     #",
        "     #",
        ])
    put_pattern(top + 40, left + 6, [
        "  # #",
        "   # ",
        "    #",
        "  ## ",
        "  #  "
        ])
    put_pattern(top + 40, left + 20, [
        "## ##"[::-1],
        "#  ##"[::-1],
        " ####"[::-1],
        "# ###"[::-1],
        " # ##"[::-1]
        ])
    board[top + 45, left + 7] = 1
    vert(top + 46, left + 6, 4)
    board[top + 49, left + 7] = 1
    horiz(top + 48, left + 8, 17)
    vert(top + 46, left + 25, 2)
    vert(top + 45, left + 24, 1)
    vert(top + 38, left + 21, 2)

    horiz(top + 43, left + 24, 4)
    vert(top + 45, left + 23, 1)

    horiz(top + 46, left + 15, 9)
    board[top + 42, left + 11] = 1
    board[top + 43, left + 12] = 1
    board[top + 44, left + 13] = 1
    board[top + 45, left + 14] = 1

    horiz(top + 39, left + 5, 4)
    vert(top + 40, left + 4, 4)
    horiz(top + 43, left, 4)

def put_left_edge(top, left):
    horiz(top + 43, left-3, 3)
    vert(top + 43, left-3, 12)
    horiz(top + 55, left-2, 2)

# Tested.
XORGATE = [
    # | |
    r"K\K\ ",
    r"|><|",
    r"A/~~",
    r"| A/",
    r"|>< ",
    r"~~  ",
    r"A/  ",
    # |
        ]

# Tested.
HALFADDER = [
    # |  |
    r"K\ K\ ",
    r"|K\|K\ ",
    r"|~><~|",
    r"|><><|",
    r"A/A/A/",
    r"~ ~ ><",
    r"><|  |",
    r" A/  |",
    #  |   |
]

def circuit_put(top, left, pattern):
    for i in range(len(pattern)):
        for j in range(len(pattern[i])):
            if pattern[i][j] != ' ':
                circuit_map[(top+i, left+j)] = pattern[i][j]

# Tested.
def full_adder(top, left):
    circuit_put(top, left+1, HALFADDER)
    circuit_put(top+9, left, HALFADDER)
    #for i in range(9):
    #    circuit_map[top+i, left] = "|"
    for i in range(5):
        circuit_map[top+8+i, left+6] = "|"
    circuit_map[top+8, left+2] = ">"
    circuit_map[top+8, left+3] = "<"
    circuit_map[top+8+6, left+4] = "~"
    circuit_map[top+8+6, left+5] = ">"
    circuit_map[top+8+6, left+6] = "<"
    circuit_map[top+8+5, left+6] = "~"
    circuit_map[top+8+7, left+4] = "A"
    circuit_map[top+8+7, left+5] = "/"
    circuit_map[top+8+8, left+4] = "~"
    circuit_map[top+8+8, left+5] = " "
    # ---0123456---
    # ---||  |  ---
    # ---ccccccc---
    # --- |  |  ---
    # ---0123456---

# Tested. (n=3)
def n_bit_tripler(top, left, n):
    for i in range(n-1, -1, -1):
        # Put adder
        full_adder(top + i * 10, left + i*6)
        # Extend inputs
        for j in range(i * 10):
            circuit_map[top + j, left + i*6 + 4] = '|'
        # Extend outputs
        for j in range(i * 10 + 17, n * 10 + 7):
            circuit_map[top + j, left + i*6 + 1] = '|'

    for i in range(n-1):
        # Join carry-out to carry-in
        circuit_map[top + i * 10 + 17, left + i * 6 + 4] = '>'
        circuit_map[top + i * 10 + 17, left + i * 6 + 5] = '<'
        circuit_map[top + i * 10 + 18, left + i * 6 + 5] = '>'
        circuit_map[top + i * 10 + 18, left + i * 6 + 6] = '<'

        # Join A_i+1 to B_i
        for j in range(6):
            circuit_map[top + i * 10 + j + 4, left + i * 6 + 7] = '|'
        circuit_map[top + i * 10 + 3, left + i * 6 + 6] = 'K'
        circuit_map[top + i * 10 + 3, left + i * 6 + 7] = '\\'

    # Put zero inputs at two left-most inputs
    circuit_map[top-1, left+1] = '0'
    circuit_map[top+8, left] = '0'

    # ---0123456789abc...
    # ---    |     |  ... (and two left-most inputs, ignore)
    # ---ccccccccccccc...
    # --- |     |     ... (and carry output, ignore)
    # ---0123456789abc...

circuit_map = {}

FLAG = "CTF{M1n0r_hIghW4y_d3t0Ur}"
print("Flag len:", len(FLAG))
#FLAG = FLAG[:2] + "\0\0\0\0"
FLAG_BITS = "".join("{:07b}".format(ord(c)) for c in FLAG)

FLAG_BITS += '0' # So that it's divisble by 16
assert len(FLAG_BITS) % 16 == 0
print("Flag bits:", FLAG_BITS)

N_BITS = len(FLAG_BITS)

#N_BITS = 16
print("n bits:", N_BITS)

if 0:
    for i in range(len(FLAG_BITS)):
        if FLAG_BITS[i] == '1':
            put_one(50, 106+28*(4+6*i))

if 0:
    put_one(50, 106+28* 4) # 1
    #put_one(50, 106+28*10) # 2
    put_one(50, 106+28*16) # 4
    #put_one(50, 106+28*22) # 8
    put_one(50, 106+28* 28) # 1
    #put_one(50, 106+28*34) # 2
    put_one(50, 106+28*40) # 4
    #put_one(50, 106+28*46) # 8

# The flag circuit.
for i in range(N_BITS):
    circuit_map[0, 6*i+4] = "|" # Ease debugging...
    circuit_map[1, 6*i+4] = "~" # Negation step.

    # flag = flag ^ (flag << 1)
    circuit_map[2, 6*i+4] = "K"
    circuit_map[2, 6*i+5] = "\\"
    circuit_map[3, 6*i+5] = '>'
    circuit_map[3, 6*i+6] = '<'
    circuit_map[3, 6*i+3] = '>'
    circuit_map[3, 6*i+4] = '<'

    circuit_map[4, 6*i+2] = '>'
    circuit_map[4, 6*i+3] = '<'
    circuit_map[4, 6*i+6] = '|'
    if i != N_BITS - 1:
        circuit_put(5, 6*i+6, XORGATE)
    else:
        circuit_map[5, 1] = '>'
        circuit_map[5, 2] = '<'
        circuit_map[6, 0] = '>'
        circuit_map[6, 1] = '<'
        for j in range(5):
            circuit_map[7+j, 0] = '|'
FLAG_BITS = "".join({"0":"1", "1":"0"}[c] for c in FLAG_BITS)
print("Negated:", FLAG_BITS)
f = [FLAG_BITS[0]]
for i in range(N_BITS-1):
    f.append(str(int(FLAG_BITS[i]) ^ int(FLAG_BITS[i+1])))
FLAG_BITS = "".join(f)
print("Xorshifted:", FLAG_BITS)

# Nibble-wise bitswap.
f = []
for i in range(0, N_BITS, 4):
    SWAP = [
        "><    |     |    >< ",
        " ><   |     |   >< ",
        "  ><  |     |  >< ",
        "   >< |     | >< ",
        "    ><|     |>< ",
        "     ><     ><  ",
        "     |><   ><|  ",
        "     ><>< ><><  ",
        "      ><><|><   ",
        "       ><><|    ",
        "        ><||    ",
        "       ><|><    ",
        "      >< ><><   ",
        "     >< ><><><  ",
        "    >< ><  ><>< ",
        "   >< ><    | >< ",
        "  ><  |     |  >< ",
        " ><   |     |   >< ",
        "><    |     |    ><      ",
        "| 11  | 11  | 11  | 11  ", # Already preparing for next stage here...
        "| A/  | A/  | A/  | A/  ",
        "| |   | |   | |   | |   ", # To be replaced with ~ perhaps.
    ]
    circuit_put(12, i*6, SWAP)
    f.append(FLAG_BITS[i:i+4][::-1])

FLAG_BITS = "".join(f)
print("Bit-swapped:", FLAG_BITS)


RANDOM_BITS1 = "10001001111001110100000010110001101100101100110010000010111111101110001000111101111100001010111110101000110111000000111001001010001100001101001001101100100011111001111100000110101010110010000010101110000110001111100100000110111100110011110000001010010010011101011111001101001011110001101001110100010110010100101101100101011101001100001111101110001101001110011000111111100000111111101010110111111011001110001001100010110101010000011000011111001111001000111111110011111000000101101010101100111011100011110010000011"
RANDOM_BITS2 = "11001010110101111000000000111001010001110100110100000011100001101100100001000010000100100111110111010000101011001100111010000100101101110110110111010110010111110000100011111000000111111101100001011001110010011110001111011000110111100010100001101011011100001100111110101010100111001000010100110101000100111000010000110001000000110110011010110000011101011100000011110000110011000110011001011011000010011010100010111011000101001001010001010011111100011110101000101111101010010100011011111000010110100011100011101101"
RANDOM_BITS3 = "11001000001001011100110010100010010111001101110001010001000010000101110011011110111111010010000101000000100110100101110010101000111101110100011111010100110010000100111110110101101001001101010110000000001111111001101101010110001110111001111110011000110111001011101010010111111110000011011011111010101100110010111101001001010111101010000000000000000100000001011000011101000110001000000101011100100110011000000101110101000000110011010100101010010001010101100000010110001001101011011010000110011111111010101010101000"

# Xor with random bits, randomly generated
f = []
for i in range(N_BITS):
    circuit_map[31, i*6 + 2] = RANDOM_BITS1[i]
    circuit_map[31, i*6 + 3] = RANDOM_BITS2[i]
    circuit_map[33, i*6 + 2] = {"0":"|","1":"~"}[RANDOM_BITS3[i]]
    circuit_put(34, i*6, XORGATE)
    f.append(str(int(RANDOM_BITS3[i]) ^ (int(RANDOM_BITS2[i]) & int(RANDOM_BITS1[i])) ^ int(FLAG_BITS[i])))

FLAG_BITS = "".join(f)
print("Random xored:", FLAG_BITS)

# Another smaller bit-swap.
f = []
for i in range(0, N_BITS, 8):
    SWAP2 = [
        "><    |    ><",
        " ><   |   >< ",
        "  ><  |  ><  ",
        "   >< | ><   ",
        "    ><|><    ",
        "     ><|     ",
        "     |><     ",
        "     ><|     ",
        "    ><|><    ",
        "   >< | ><   ",
        "  ><  |  ><  ",
        " ><   |   >< ",
        "><    |    ><",
    ]
    circuit_put(41, i*6, SWAP2)
    circuit_put(41, i*6 + 18, SWAP2)
    for j in range(13):
        circuit_map[41+j, i*6+36] = '|'
        circuit_map[41+j, i*6+42] = '|'
    f.append(FLAG_BITS[i:i+3][::-1])
    f.append(FLAG_BITS[i+3:i+6][::-1])
    f.append(FLAG_BITS[i+6:i+8])

FLAG_BITS = "".join(f)
print("Bit-swapped:", FLAG_BITS)

# Tripler.
for i in range(N_BITS):
    circuit_map[54, i*6] = '>'
    circuit_map[54, i*6+1] = '<'
    circuit_map[55, i*6+1] = '>'
    circuit_map[55, i*6+2] = '<'
    circuit_map[56, i*6+2] = '>'
    circuit_map[56, i*6+3] = '<'
    circuit_map[57, i*6+3] = '>'
    circuit_map[57, i*6+4] = '<'

n_bit_tripler(58, 0, N_BITS)

f = int(FLAG_BITS[::-1], 2)
f *= 3
f &= (2**N_BITS - 1)
FLAG_BITS = ("{:0%db}" % N_BITS).format(f)[::-1]
print("Tripled:", FLAG_BITS)

top = 58 + N_BITS*10 + 7

# Nibble-wise bitswap, misaligned to thwart byte-by-byte attack.
f = []
for i in range(0, N_BITS, 16):
    SWAP = [
        "><    |     |    >< ",
        " ><   |     |   >< ",
        "  ><  |     |  >< ",
        "   >< |     | >< ",
        "    ><|     |>< ",
        "     ><     ><  ",
        "     |><   ><|  ",
        "     ><>< ><><  ",
        "      ><><|><   ",
        "       ><><|    ",
        "        ><||    ",
        "       ><|><    ",
        "      >< ><><   ",
        "     >< ><><><  ",
        "    >< ><  ><>< ",
        "   >< ><    | >< ",
        "  ><  |     |  >< ",
        " ><   |     |   >< ",
        "><    |     |    ><      ",
    ]
    circuit_put(top, i*6 + 6 * 6 + 1, SWAP)
    for j in range(19):
        for k in range(6):
            circuit_map[top+j, i*6 + k*6 + 1] = '|'
            circuit_map[top+j, i*6 + k*6 + 1 + 6*10] = '|'
    f.append(FLAG_BITS[i:i+6])
    f.append(FLAG_BITS[i+6:i+10][::-1])
    f.append(FLAG_BITS[i+10:i+16])

FLAG_BITS = "".join(f)
print("Bit-swapped:", FLAG_BITS)
FINAL_BITS = FLAG_BITS

top += 19

for i in range(N_BITS):
    circuit_map[top, i * 6 + 1] = {"0":'~', "1":"|"}[FINAL_BITS[i]]

print("Final:", "1" * N_BITS)

# Final AND of the n bits.
for i in range(N_BITS - 1):
    for j in range(i+1, N_BITS):
        circuit_map[top+1 + 6*i, 6*(N_BITS-1-j)+1] = '|'
        circuit_map[top+2 + 6*i, 6*(N_BITS-1-j)+1] = '|'
        circuit_map[top+3 + 6*i, 6*(N_BITS-1-j)+1] = '|'
        circuit_map[top+4 + 6*i, 6*(N_BITS-1-j)+1] = '|'
        circuit_map[top+5 + 6*i, 6*(N_BITS-1-j)+1] = '|'
        circuit_map[top+6 + 6*i, 6*(N_BITS-1-j)+1] = '|'
    circuit_map[top+1 + 6*i, 6*(N_BITS-1-i)] = '>'
    circuit_map[top+1 + 6*i, 6*(N_BITS-1-i)+1] = '<'
    circuit_map[top+2 + 6*i, 6*(N_BITS-1-i)-1] = '>'
    circuit_map[top+2 + 6*i, 6*(N_BITS-1-i)+0] = '<'
    circuit_map[top+3 + 6*i, 6*(N_BITS-1-i)-2] = '>'
    circuit_map[top+3 + 6*i, 6*(N_BITS-1-i)-1] = '<'
    circuit_map[top+4 + 6*i, 6*(N_BITS-1-i)-3] = '>'
    circuit_map[top+4 + 6*i, 6*(N_BITS-1-i)-2] = '<'
    circuit_map[top+5 + 6*i, 6*(N_BITS-1-i)-4] = '>'
    circuit_map[top+5 + 6*i, 6*(N_BITS-1-i)-3] = '<'
    circuit_map[top+6 + 6*i, 6*(N_BITS-1-i)-5] = 'A'
    circuit_map[top+6 + 6*i, 6*(N_BITS-1-i)-4] = '/'

circuit_map[top+7 + 6*i, 6*(N_BITS-1-i)-6] = '>'
circuit_map[top+7 + 6*i, 6*(N_BITS-1-i)-5] = '<'

print("Circuit constructed.")

RANDOM_BACKGROUND = True

mk0 = max(k[0] for k in circuit_map)
mk1 = max(k[1] for k in circuit_map)
print("circuit size", mk0, mk1)

circuit = [[" "] * (1+mk1) for j in range(1+mk0)]

for i, j in circuit_map:
    circuit[i][j] = circuit_map[i,j]

circuit = ["".join(line) for line in circuit]

print("Circuit ASCII-written.")

#board = defaultdict(int)
import numpy as np
board = np.zeros((mk0 * 50 + 400, mk1 * 28 + 400), dtype=np.uint8)

horiz(55, 76, 24) # Start of the circuit, on the highway. Entry: 56,100 facing right. (or 56, 56*2!)

for i, line in enumerate(circuit):
    if i % 100 == 0:
        print(i, "/", len(circuit))
    line = line.split("#")[0]
    ii = 50 + 50 * i
    if i != len(circuit) - 1:
        put_left_edge(ii, 100)
        put_right_edge(ii, 100 + 28 * len(line))
    j = 0
    while j < len(line):
        c = line[j]
        jj = 100 + 28 * j
        if c == 'A':
            assert line[j+1] == "/"
            put_AND(ii, jj)
            j += 2
            continue
        elif c == ">":
            assert line[j+1] == "<"
            put_CROSS(ii, jj)
            j += 2
            continue
        elif c == "K":
            assert line[j+1] == "\\"
            put_SPLIT(ii, jj)
            j += 2
            continue
        elif c == "0":
            put_ZERO(ii, jj)
        elif c == "1":
            put_ONE(ii, jj)
        elif c == "|":
            put_PASS(ii, jj)
        elif c == "~":
            put_NOT(ii, jj)
        elif c == ' ':
            if not RANDOM_BACKGROUND:
                put_ZERO(ii, jj)
            else:
                if j == len(line) - 1 or line[j+1] != ' ':
                    which = random.choice(["0", "1", "|", "~"])
                else:
                    which = random.choice(["0", "1", "|", "~", "A/", "><", "K\\"])
                line = line[:j] + which + line[j+len(which):]
                circuit[i] = line
                continue
        else:
            print(c)
            assert False

        j += 1

print("Circuit mapped.")

open("board.txt", "w").write("\n".join(circuit) + "\n")

end_j, end_i = 100 + 28 * len(circuit[0]), 50 + 5 + 50 * (len(circuit) - 1)

where = np.argwhere(board == 1)
max_y = where[:, 0].max()
max_x = where[:, 1].max()
max_y += 64 - max_y % 8
max_x += 64 - max_x % 8

print(max_y, max_x)

# Quick optimization to speed up the final tight loop.
import numpy as np
import json
arr = board[:max_y, :max_x]

arr2 = np.zeros((max_y, max_x//8), dtype=np.uint8)
for i in range(8):
    arr2 |= arr[:,i::8] << i
# 27G of ram?
print("Numpy preprocessing done.")

with open(sys.argv[1], "w") as f:
    f.write("#define SZY %d\n" % max_y)
    f.write("#define SZX %d\n" % max_x)
    f.write("char board[SZY][SZX / 8 + 1] = {\n");
    for i in range(max_y):
        if i % 500 == 0:
            print(i, "/", max_y)
        f.write("{")
        # There we go!
        f.write(json.dumps(arr2[i].tolist())[1:-1])
        f.write("},\n");
    f.write("};\n")

    if 0:
        f.write("const char* circuit[%d] = {\n" % (len(circuit) + 1))
        for line in circuit:
            f.write('%s,' % json.dumps(line))
        f.write('""};\n')

    f.write("#define CIRCUIT_WIDTH %d\n" % (len(circuit[0])))
    f.write("#define CIRCUIT_HEIGHT %d\n" % (len(circuit)))

    #f.write("#define EXIT_COND (y == 55 && x > 90)\n")
    f.write("#define EXIT_COND (x == %d && y == %d)\n" % (end_j, end_i))

print("C header written.")

if 0:
    # Commented out for final version, as I get BadAllocs...
    import matplotlib.pyplot as plt
    import numpy as np
    brd = np.zeros((max_y, max_x))
    for i in range(max_y):
        for j in range(max_x):
            brd[i,j] = board[i,j]
    plt.figure(figsize=(len(circuit[0]), len(circuit)))
    plt.imshow(brd)
    plt.savefig("board.png", bbox_inches='tight')
    print("Image written.")
