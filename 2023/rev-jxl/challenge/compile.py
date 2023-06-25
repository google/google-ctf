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

from collections import defaultdict


mp = defaultdict(lambda: defaultdict(lambda: "Set 0"))

def put_doubler(y, x):
    # Doubles (y, x) to (y+2, x)
    mp[y+1][x] = "N +INF1"
    mp[y+2][x-1] = "NE -INF2"
    mp[y+2][x] = "Gradient +0"

def put_adder(y, x):
    # Add (y, x) and (y+2, x-2), putting result at (y+2, x)
    mp[y+1][x] = "N +INF1"
    mp[y+2][x-1] = "W -INF1"
    mp[y+2][x] = "Gradient +0"

def put_negate(y, x):
    # Negate (y, x) to (y+1, x+1)
    mp[y+1][x] = "Set +INF1"
    mp[y][x+1] = "Set -INF1"
    mp[y+1][x+1] = "Gradient +0"

def put_multiplier(y, x, n_bits, const):
    # Input at (y, x)
    # Passthrough to (y + (n-1)*2, x)
    # Output at (y+(n-1)*2, x+4)
    mp[y][x+1] = "W +0"
    mp[y][x+2] = "W +0"
    if const & 1:
        mp[y][x+3] = "W +0"
        mp[y][x+4] = "W +0"

    for i in range(n_bits-1):
        mp[y+2*i+1][x] = "N +0"
        mp[y+2*i+2][x] = "N +0"
        put_doubler(y+2*i, x+2)
        put_adder(y+2*i, x+4)
        if not (const & (1<<(i+1))):
            mp[y+2*i+2][x+3] = "Set -INF1"

NEGATIVE = True
def put_flag(y, x, flag):
    # C
    mp[y][x] = "Set WHITE"
    mp[y][x+1] = "Set WHITE"
    mp[y][x+2] = "Set WHITE"
    mp[y+1][x] = "Set WHITE"
    mp[y+2][x] = "Set WHITE"
    mp[y+2][x+1] = "Set WHITE"
    mp[y+2][x+2] = "Set WHITE"
    # T
    mp[y][x+5] = "Set WHITE"
    mp[y][x+6] = "Set WHITE"
    mp[y][x+7] = "Set WHITE"
    mp[y+1][x+6] = "Set WHITE"
    mp[y+2][x+6] = "Set WHITE"
    # F
    mp[y][x+10] = "Set WHITE"
    mp[y][x+11] = "Set WHITE"
    mp[y][x+12] = "Set WHITE"
    mp[y+1][x+10] = "Set WHITE"
    mp[y+1][x+11] = "Set WHITE"
    mp[y+2][x+10] = "Set WHITE"
    # {
    mp[y][x+16] = "Set WHITE"
    mp[y+1][x+16] = "Set WHITE"
    mp[y+2][x+16] = "Set WHITE"
    mp[y+1][x+15] = "Set WHITE"
    mp[y][x+17] = "Set WHITE"
    mp[y+2][x+17] = "Set WHITE"

    n_underscores = len(flag) - 5
    # Underscores
    for i in range(n_underscores):
        mp[y+2][x+20+5*i] = "Set WHITE"
        mp[y+2][x+21+5*i] = "Set WHITE"
        mp[y+2][x+22+5*i] = "Set WHITE"

    xx = x + n_underscores * 5
    # }
    mp[y][xx+20] = "Set WHITE"
    mp[y][xx+21] = "Set WHITE"
    mp[y+1][xx+21] = "Set WHITE"
    mp[y+1][xx+22] = "Set WHITE"
    mp[y+2][xx+21] = "Set WHITE"
    mp[y+2][xx+20] = "Set WHITE"

    for i in range(len(flag)):
        c = ord(flag[i])
        for j in range(8):
            if c & (1<<(7-j)):
                mp[y+4+j][x+5*i+1] = "Set WHITE"

        for j in range(0, 8, 2):
            top = 1<<(7-j)
            bottom = 1<<(6-j)

            top *= 4
            bottom *= 4

            # Squeezing the pixels...
            mp[y+5+j][x+5*i+2] = """
            if W > 0
                if W-NW > 0
                    - Set %d
                    - Set %d
                if W-NW > -1
                    - Set %d
                    - Set %d
                    """ % (bottom, top+bottom, 0, top)
        for j in range(0, 8, 4):
            mp[y+6+j][x+5*i+2] = "N +0"
            mp[y+7+j][x+5*i+3] = "AvgW+NW +0"

        mp[y+8][x+5*i+3] = "N +0"
        mp[y+9][x+5*i+3] = "N +0"
        mp[y+10][x+5*i+3] = "N +0"
        mp[y+11][x+5*i+4] = "AvgW+NW +0"
        mp[y+12][x+5*i+3] = "NE +0"
        mp[y+13][x+5*i+2] = "NE +0"
        mp[y+14][x+5*i+1] = "NE +0"
        if NEGATIVE:
            put_negate(y+14, x+5*i+1)
        else:
            mp[y+15][x+5*i+2] = "NW +0"
        mp[y+16][x+5*i+1] = "NE +0"



# ------

#TODO: make sure the flag is dummy in release
FLAG = "CTF{JPEG_XL_1s_tur1ng_c0mplet3!}"
FLAG = "CTF{___________________________}"
#FLAG = "CTF{JP}"
print("Flag length:", len(FLAG))

put_flag(0, 0, FLAG)

if 0:
    multipliers = [[] for i in range(27)]
    expected = [0] * 27
    for i in range(0, 27):
        multipliers[i] = [0] * 32
        expected[i] = 0
    # For some reason this works only up to 2+7th char, not later...
    # Probably not overflow, since it doesn't depend on the factor of 15 there.
    for j in range(4, 4+14):
        multipliers[0][j] = 15
    s = sum(ord(c) for c in "JPEG_XL_1s_tur1ng_c0mplet3!"[0:14])
    print(s)
    expected[0] = s * 15

elif 1:
    # Generated using gen_eqs.py
    multipliers = [[0, 0, 0, 0, 12, 15, 5, 3, 14, 1, 15, 0, 13, 15, 14, 6, 0, 2, 4, 15, 10, 9, 12, 12, 5, 14, 14, 13, 3, 0, 7, 0], [0, 0, 0, 0, 5, 9, 3, 12, 0, 15, 1, 14, 0, 4, 15, 2, 6, 11, 4, 4, 15, 2, 9, 1, 4, 7, 2, 0, 0, 5, 13, 0], [0, 0, 0, 0, 6, 4, 14, 5, 7, 4, 11, 15, 3, 5, 8, 13, 10, 11, 7, 14, 3, 14, 2, 14, 12, 4, 14, 9, 10, 4, 10, 0], [0, 0, 0, 0, 1, 13, 10, 8, 9, 2, 1, 6, 11, 5, 1, 14, 10, 6, 4, 12, 12, 2, 0, 8, 8, 15, 12, 5, 3, 10, 9, 0], [0, 0, 0, 0, 12, 1, 7, 7, 0, 10, 6, 2, 9, 12, 6, 11, 10, 1, 7, 15, 15, 8, 15, 6, 5, 11, 5, 3, 0, 0, 0, 0], [0, 0, 0, 0, 1, 14, 10, 15, 12, 8, 12, 5, 13, 1, 15, 1, 15, 11, 0, 10, 2, 9, 13, 1, 4, 2, 8, 4, 10, 7, 0, 0], [0, 0, 0, 0, 13, 10, 11, 1, 12, 0, 8, 13, 0, 10, 15, 8, 0, 11, 9, 4, 8, 2, 12, 3, 11, 8, 1, 8, 0, 13, 0, 0], [0, 0, 0, 0, 1, 1, 11, 6, 6, 15, 15, 13, 1, 11, 10, 7, 13, 13, 13, 15, 6, 12, 11, 8, 6, 7, 6, 4, 9, 13, 9, 0], [0, 0, 0, 0, 0, 9, 5, 5, 12, 4, 13, 15, 2, 2, 9, 2, 2, 8, 0, 14, 0, 1, 2, 8, 8, 15, 1, 4, 5, 3, 4, 0], [0, 0, 0, 0, 8, 2, 14, 12, 1, 12, 8, 10, 11, 0, 3, 6, 3, 5, 3, 0, 0, 8, 3, 15, 9, 8, 6, 0, 0, 5, 13, 0], [0, 0, 0, 0, 10, 14, 8, 13, 1, 7, 7, 12, 8, 12, 11, 3, 4, 3, 13, 13, 4, 2, 12, 0, 11, 9, 6, 1, 12, 6, 9, 0], [0, 0, 0, 0, 0, 11, 8, 4, 2, 4, 13, 5, 6, 6, 11, 3, 8, 1, 10, 8, 2, 1, 11, 9, 12, 3, 5, 14, 0, 15, 4, 0], [0, 0, 0, 0, 6, 10, 11, 1, 6, 3, 5, 4, 0, 6, 1, 14, 12, 15, 7, 6, 14, 0, 14, 10, 15, 13, 0, 15, 6, 0, 14, 0], [0, 0, 0, 0, 3, 15, 10, 14, 12, 13, 12, 4, 13, 6, 10, 7, 11, 5, 11, 6, 15, 13, 8, 13, 12, 0, 14, 11, 14, 8, 3, 0], [0, 0, 0, 0, 0, 14, 7, 1, 10, 5, 12, 6, 5, 3, 9, 12, 1, 15, 6, 5, 1, 2, 10, 10, 12, 9, 15, 4, 5, 0, 5, 0], [0, 0, 0, 0, 2, 5, 12, 1, 9, 15, 12, 9, 5, 4, 5, 2, 1, 6, 7, 9, 11, 5, 7, 2, 15, 0, 13, 7, 13, 3, 3, 0], [0, 0, 0, 0, 0, 11, 9, 8, 14, 5, 12, 2, 13, 8, 14, 7, 7, 10, 13, 1, 3, 0, 9, 5, 2, 11, 12, 8, 10, 2, 11, 0], [0, 0, 0, 0, 8, 6, 7, 2, 11, 3, 8, 5, 3, 0, 3, 14, 15, 2, 6, 11, 11, 12, 15, 10, 10, 13, 6, 14, 14, 0, 0, 0], [0, 0, 0, 0, 0, 6, 14, 10, 9, 5, 11, 13, 14, 5, 14, 3, 13, 9, 11, 10, 10, 5, 14, 2, 0, 15, 4, 12, 8, 10, 12, 0], [0, 0, 0, 0, 8, 8, 15, 15, 11, 15, 1, 5, 0, 0, 10, 15, 0, 1, 2, 8, 0, 4, 2, 3, 8, 5, 14, 7, 3, 12, 13, 0], [0, 0, 0, 0, 14, 0, 7, 13, 15, 6, 3, 10, 7, 10, 2, 6, 8, 13, 0, 0, 13, 11, 3, 0, 2, 4, 14, 14, 12, 8, 13, 0], [0, 0, 0, 0, 15, 2, 2, 15, 2, 9, 13, 14, 2, 15, 2, 2, 9, 3, 14, 6, 9, 13, 3, 2, 0, 7, 4, 15, 4, 5, 7, 0], [0, 0, 0, 0, 6, 4, 6, 9, 10, 14, 14, 15, 8, 10, 9, 7, 13, 13, 1, 3, 0, 1, 2, 2, 12, 10, 8, 11, 15, 10, 15, 0], [0, 0, 0, 0, 1, 1, 6, 15, 5, 5, 6, 6, 6, 15, 4, 13, 2, 0, 14, 8, 2, 4, 6, 9, 3, 3, 1, 13, 15, 6, 10, 0], [0, 0, 0, 0, 12, 5, 2, 7, 1, 2, 9, 4, 14, 10, 14, 11, 6, 3, 2, 10, 13, 14, 11, 10, 0, 5, 2, 9, 2, 2, 0, 0], [0, 0, 0, 0, 13, 10, 2, 7, 9, 15, 3, 6, 15, 12, 10, 11, 2, 6, 1, 1, 10, 1, 11, 11, 7, 3, 10, 6, 1, 3, 13, 0], [0, 0, 0, 0, 5, 11, 5, 3, 8, 0, 10, 4, 3, 6, 3, 14, 10, 6, 8, 13, 1, 11, 10, 15, 15, 0, 12, 5, 14, 13, 5, 0]]
    expected = [20832, 14378, 21040, 17570, 17116, 18423, 17233, 21695, 14032, 12853, 18501, 14835, 19266, 23085, 16902, 16838, 17965, 20102, 20792, 15792, 18872, 16995, 20616, 15353, 16199, 17013, 18876]
else:
    expected = [ord('J') + ord('P')] * 27
    multipliers = []
    for i in range(27):
        multipliers.append([])
        for j in range(32):
            multipliers[-1].append(0)
        multipliers[-1][5] = 1
        multipliers[-1][4] = 1
print(len(multipliers))
print(len(expected))
print(multipliers)


if NEGATIVE:
    expected = [-e for e in expected]

N_BITS = 4
START_LETTER = 4
END_LETTER = len(FLAG) - 1

for i in range(len(multipliers)):
    y = 14 + i * (N_BITS * 2 + 1) + 2
    for j in range(START_LETTER, END_LETTER):
        x = 1 + j * 5
        put_multiplier(y, x, N_BITS, multipliers[i][j])
        # Output at (y+(n-1)*2, x+4)
        put_adder(y+(N_BITS-1)*2, x+4)
        # Add (y, x) and (y+2, x-2), putting result at (y+2, x)
        mp[y+N_BITS*2][x+1] = "WW +0"
        mp[y+N_BITS*2][x+2] = "W +0"
        mp[y+N_BITS*2-1][x] = "N +0"
        mp[y+N_BITS*2][x] = "N +0"
        mp[y+N_BITS*2+1][x] = "N +0"

    m = END_LETTER-1
    mp[y+N_BITS*2][6 + m * 5] = "if W > %d\n- Set 0\nif W > %d\nif N > 0\n- Set 1\n- Set 0\n- Set 0" % (expected[i], expected[i]-1)

    if i != 0:
        # Pass is_correct
        for j in range(N_BITS * 2):
            mp[y+j][6+m*5] = "N +0"
    else:
        # Initialize is_correct.
        mp[y+N_BITS*2-1][6+m*5] = "Set 1"




y = 14 + len(multipliers) * (N_BITS * 2 + 1) + 2
x = 6 + 5 * END_LETTER - 5

for i in range(28):
    mp[y+i][x-1-i] = "NE +0"

for i in range(6):
    mp[y+28+i][x-1-27] = "N +0"

mp[y+28+3][x-1-27] = "if N > 0\n- Set 0\n- Set 1"

FLAG_Y = y + 27
FLAG_X = x - 27
print(FLAG_Y, FLAG_X)


mp_background_R = defaultdict(lambda: defaultdict(lambda: "Set 0"))
mp_background_G = defaultdict(lambda: defaultdict(lambda: "Set 0"))


for k in range(2):
    x = 5 * END_LETTER - 25
    if k == 0:
        m = mp_background_G
        y = 14 + len(multipliers) * (N_BITS * 2 + 1) + 34 - 5
    else:
        m = mp_background_R
        y = 14 + len(multipliers) * (N_BITS * 2 + 1) + 38 - 5

    # F
    m[y][x] = "Set WHITE"
    m[y+1][x] = "Set WHITE"
    m[y+2][x] = "Set WHITE"
    m[y][x+1] = "Set WHITE"
    m[y+1][x+1] = "Set WHITE"
    m[y][x+2] = "Set WHITE"

    # L
    m[y][x+4] = "Set WHITE"
    m[y+1][x+4] = "Set WHITE"
    m[y+2][x+4] = "Set WHITE"
    m[y+2][x+5] = "Set WHITE"

    # A
    m[y][x+7] = "Set WHITE"
    m[y+1][x+7] = "Set WHITE"
    m[y+2][x+7] = "Set WHITE"
    m[y][x+8] = "Set WHITE"
    m[y+1][x+8] = "Set WHITE"
    m[y][x+9] = "Set WHITE"
    m[y+1][x+9] = "Set WHITE"
    m[y+2][x+9] = "Set WHITE"

    # G
    m[y][x+11] = "Set WHITE"
    m[y+1][x+11] = "Set WHITE"
    m[y+2][x+11] = "Set WHITE"
    m[y][x+12] = "Set WHITE"
    m[y+2][x+12] = "Set WHITE"
    m[y+1][x+13] = "Set WHITE"
    m[y+2][x+13] = "Set WHITE"

    if k == 0:
        # O
        m[y][x+17] = "Set WHITE"
        m[y][x+18] = "Set WHITE"
        m[y][x+19] = "Set WHITE"
        m[y+2][x+17] = "Set WHITE"
        m[y+2][x+18] = "Set WHITE"
        m[y+2][x+19] = "Set WHITE"
        m[y+1][x+17] = "Set WHITE"
        m[y+1][x+19] = "Set WHITE"

        # K
        m[y][x+21] = "Set WHITE"
        m[y][x+23] = "Set WHITE"
        m[y+2][x+21] = "Set WHITE"
        m[y+2][x+23] = "Set WHITE"
        m[y+1][x+21] = "Set WHITE"
        m[y+1][x+22] = "Set WHITE"
    else:
        # B
        m[y][x+17] = "Set WHITE"
        m[y][x+18] = "Set WHITE"
        m[y+1][x+18] = "Set WHITE"
        m[y+2][x+17] = "Set WHITE"
        m[y+2][x+18] = "Set WHITE"
        m[y+2][x+19] = "Set WHITE"
        m[y+1][x+17] = "Set WHITE"
        m[y+1][x+19] = "Set WHITE"

        # A
        m[y][x+21] = "Set WHITE"
        m[y][x+22] = "Set WHITE"
        m[y][x+23] = "Set WHITE"
        m[y+2][x+21] = "Set WHITE"
        m[y+2][x+23] = "Set WHITE"
        m[y+1][x+21] = "Set WHITE"
        m[y+1][x+22] = "Set WHITE"
        m[y+1][x+23] = "Set WHITE"

        # D
        m[y][x+25] = "Set WHITE"
        m[y][x+26] = "Set WHITE"
        m[y+2][x+25] = "Set WHITE"
        m[y+1][x+25] = "Set WHITE"
        m[y+2][x+26] = "Set WHITE"
        m[y+1][x+27] = "Set WHITE"



def compile_mp(mp):
    min_y = min(k for k in mp)
    max_y = max(k for k in mp)
    prev_row = None

    rows = []

    for y in range(max_y+1, min_y-1, -1):
      if not mp[y]:
        row = ["  - Set 0"]
      else:
        row = []
        min_x = min(k for k in mp[y])
        max_x = max(k for k in mp[y])
        prev_x = None
        for x in range(max_x+1, min_x-1, -1):
          if mp[y][x] != prev_x:
            row.append("  if x > %d" % (x-1))
            if mp[y][x].strip().startswith("if"):
                row.append(mp[y][x])
            else:
                row.append("  - %s" % mp[y][x])
          else:
            row[-2] = "  if x > %d" % (x-1)
          prev_x = mp[y][x]
        row.append("  - Set 0")

      row = "\n".join(row)
      if row == prev_row:
        rows[-2] = "if y > %d" % (y-1)
      else:
        rows.append("if y > %d" % (y-1))
        rows.append(row)
      prev_row = row

    rows.append("- Set 0")
    return rows


alpha_mp = """
if y > %d
  - Set WHITE /* below flag */
if y > %d
  /* flaggish */
  if x > %d
    - W +0
  if x > %d
    /* border */
    if Prev > 0
      - Set 0
      - Set WHITE
  - Set WHITE
- Set WHITE /* above flag */
""" % (FLAG_Y+6, FLAG_Y-1, FLAG_X-1, FLAG_X-2)
#alpha_mp = "- Set 40000"

prefix = """
RCT 0
Width 512
Height 512
Bitdepth 8
Alpha

NotLast


if c > 2
  - Set WHITE /* alpha always full */
if c > 1
  - Set 0
if c > 0
%s
%s

/* Second layer: the circuit */
NotLast

if c > 2
  %s
""" % ("\n".join(compile_mp(mp_background_G)), "\n".join(compile_mp(mp_background_R)), alpha_mp)

ss = ""
for i in range(40, 0, -1):
    ss += "if x > %d\n- Set WHITE\nif x > %d\n- Set 0\n" % (i*5-4, i*5-5)

suffix = """


/* Fourth layer: censorship bar and some spline art */

/* J */
Spline
    10 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4
    20 40
    100 40
    100 140
    60 160
    20 140
EndSpline
/* X */
Spline
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    10 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 -4
    320 320
    160 160
EndSpline
Spline
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    10 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 -4
    160 320
    320 160
EndSpline
/* L */
Spline
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    10 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0
    0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 4
    380 340
    380 480
    480 480
EndSpline

if c > 2
  if y > 300
    - Set WHITE
  if y > 285
    if x > 160
        - Set WHITE
    if x > 129
        - Set 0
        - Set WHITE
  if y > 11
    - Set WHITE
  if y > 2
    %s
    - Set 0
  - Set 0
- Set 0 /* Set to 128 if you want to see where we censor */
""" % ss

#suffix = "\n- Set 0\n"

s = prefix + "\n".join(compile_mp(mp)) + suffix
# This is technically out of spec, as only values up to 2^Bitdepth are supported.
# In practice, it works fine...
s = s.replace("INF1", "300000").replace("INF2", "600000").replace("WHITE", "65535")

open("in2.txt", "w").write(s)

# TODO after the CTF, publish the file to the JXL art discord :)
