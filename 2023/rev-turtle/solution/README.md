# Google CTF 2023 - RE: Turtle writeup

*Note: this writeup was created by a challenge tester during our internal test run*

In the task we get a Python script using turtles (like the LOGO language). It first
draws two PNG pictures we also have given.

We can notice there are four turtles created.
- mTurt first draws the 25x21 rectangle, mostly from m.png, but with the flag we give at the top (represented as pixel colors)
- sTurt draws a long and thin pink line on the left.
- rTurt draws a 3x3 dot matrix on the right.
- cTurt draws 9x86 image, c.png

Looking at the code, we can notice a distinctive dispatch loop in the run function.
It appears that the turtles actually implement some kind of virtual machine.
After reading the code in detail, we can figure out what the turtles are used as:
- mTurt is a memory, initialized by m.png and our candidate flag.
- sTurt is a stack, used for local variables and 2D return address
- rTurt reads and writes registers, the last 3 of which are condition flags (`==, <, >`)
- cTurt reads code, from c.png

We implemented a disassembler for the VM in the `disas.py` file. The code only
contains several CALL instructions, and all of them point to the very top of the
image. So that means every third column (as opcodes are three pixel large)
is a separate function.

Here's the raw output from `disas.py`:
```
00:                DROP -83 VALUES                   MOV reg_2, 4                 DROP -4 VALUES 
01:              MOV reg_2, MEM[0]           MOV STACK[-2], reg_2               MOV reg_4, reg_1 
02:                  CMP reg_2, 67               MOV STACK[-3], 0             MOV STACK[], reg_0 
03:               JUMP BY 13 IF !=           MOV reg_2, STACK[-3]               MOV reg_2, reg_5 
04:              MOV reg_2, MEM[1]                  CMP reg_2, 29               MOV reg_5, reg_4 
05:                  CMP reg_2, 84                JUMP BY 13 IF >            MOV STACK[2], reg_5 
06:               JUMP BY 10 IF !=           MOV reg_2, STACK[-3]            MOV STACK[1], reg_2 
07:              MOV reg_2, MEM[2]               MOV reg_5, reg_2            MOV reg_2, MEM[519] 
08:                  CMP reg_2, 70           MOV reg_2, STACK[-2]                 CMP reg_2, 424 
09:                JUMP BY 7 IF !=               ADD reg_5, reg_2                JUMP BY 2 IF != 
10:              MOV reg_2, MEM[3]           MOV reg_2, STACK[-3]                           LOSE 
11:                 CMP reg_2, 123                  MOV reg_4, 65                CMP STACK[1], 0 
12:                JUMP BY 4 IF !=    MOV reg_2, MEM[reg_2+reg_4]                JUMP BY 9 IF != 
13:             MOV reg_2, MEM[34]          MOV reg_5, MEM[reg_5]            MOV reg_2, MEM[519] 
14:                 CMP reg_2, 125                  MOV reg_4, 35             MOV reg_5, reg_2+1 
15:                JUMP BY 2 IF ==    MOV MEM[reg_2+reg_4], reg_5            MOV MEM[519], reg_5 
16:                           LOSE               ADD STACK[-3], 1                  MOV reg_5, 95 
17:                MOV STACK[1], 0                    JUMP BY -14    MOV reg_2, MEM[reg_2+reg_5] 
18:               CMP STACK[1], 79              RETURN THISFUN 18                   CMP reg_2, 4 
19:                 JUMP BY 5 IF >                            NOP               JUMP BY 65 IF == 
20:            MOV reg_2, STACK[1]                            NOP                           LOSE 
21:          MOV STACK[reg_2+3], 0                            NOP            MOV reg_2, STACK[1] 
22:                ADD STACK[1], 1                            NOP                   SUB reg_2, 1 
23:                     JUMP BY -5                            NOP               MOV reg_5, reg_2 
24:                MOV STACK[2], 4                            NOP                  SHR reg_5, 31 
25:            MOV reg_2, STACK[2]                            NOP               ADD reg_2, reg_5 
26:                  CMP reg_2, 28                            NOP                   SHR reg_2, 1 
27:                JUMP BY 27 IF >                            NOP            MOV STACK[3], reg_2 
28:            MOV reg_2, STACK[2]                            NOP            MOV reg_5, STACK[3] 
29:                   MOV reg_5, 0                            NOP             MOV reg_2, STACK[] 
30:    MOV reg_2, MEM[reg_2+reg_5]                            NOP               ADD reg_2, reg_5 
31:                  CMP reg_2, 42                            NOP          MOV reg_2, MEM[reg_2] 
32:              JUMP BY 6 IF ==,<                            NOP            CMP STACK[2], reg_2 
33:            MOV reg_2, STACK[2]                            NOP             JUMP BY 16 IF ==,> 
34:                   MOV reg_5, 0                            NOP            MOV reg_2, MEM[519] 
35:    MOV reg_2, MEM[reg_2+reg_5]                            NOP             MOV reg_5, reg_2+1 
36:                 CMP reg_2, 122                            NOP            MOV MEM[519], reg_5 
37:              JUMP BY 2 IF ==,<                            NOP                  MOV reg_5, 95 
38:                           LOSE                            NOP    MOV reg_2, MEM[reg_2+reg_5] 
39:            MOV reg_2, STACK[2]                            NOP                   CMP reg_2, 1 
40:                   MOV reg_5, 0                            NOP                JUMP BY 2 IF == 
41:    MOV reg_2, MEM[reg_2+reg_5]                            NOP                           LOSE 
42:                  SUB reg_2, 43                            NOP            MOV reg_5, STACK[3] 
43:      MOV reg_2, STACK[reg_2+3]                            NOP            MOV reg_2, STACK[2] 
44:               CMP reg_2, 65025                            NOP             MOV reg_4, STACK[] 
45:                JUMP BY 2 IF !=                            NOP               MOV reg_0, reg_4 
46:                           LOSE                            NOP               MOV reg_1, reg_2 
47:            MOV reg_2, STACK[2]                            NOP             CALL RIGHT 0 UP 47 
48:                   MOV reg_5, 0                            NOP                     JUMP BY 36 
49:    MOV reg_2, MEM[reg_2+reg_5]                            NOP            MOV reg_5, STACK[3] 
50:                  SUB reg_2, 43                            NOP             MOV reg_2, STACK[] 
51:      MOV STACK[reg_2+3], 65025                            NOP               ADD reg_2, reg_5 
52:                ADD STACK[2], 1                            NOP          MOV reg_2, MEM[reg_2] 
53:                    JUMP BY -28                            NOP            CMP STACK[2], reg_2 
54:             CALL RIGHT 3 UP 54                            NOP             JUMP BY 22 IF ==,< 
55:                MOV MEM[519], 0                            NOP            MOV reg_2, MEM[519] 
56:                MOV STACK[], 43                            NOP             MOV reg_5, reg_2+1 
57:               CMP STACK[], 122                            NOP            MOV MEM[519], reg_5 
58:                JUMP BY 10 IF >                            NOP                  MOV reg_5, 95 
59:             MOV reg_2, STACK[]                            NOP    MOV reg_2, MEM[reg_2+reg_5] 
60:                  MOV reg_5, 30                            NOP                   CMP reg_2, 2 
61:                  MOV reg_0, 35                            NOP                JUMP BY 2 IF == 
62:               MOV reg_1, reg_2                            NOP                           LOSE 
63:             CALL RIGHT 6 UP 63                            NOP            MOV reg_2, STACK[1] 
64:             MOV reg_2, STACK[]                            NOP            SUB reg_2, STACK[3] 
65:                   ADD reg_2, 1                            NOP                   SUB reg_2, 1 
66:             MOV STACK[], reg_2                            NOP               MOV reg_5, reg_2 
67:                    JUMP BY -10                            NOP            MOV reg_2, STACK[3] 
68:                            WIN                            NOP             MOV reg_4, reg_2+1 
69:                            NOP                            NOP             MOV reg_2, STACK[] 
70:                            NOP                            NOP               ADD reg_4, reg_2 
71:                            NOP                            NOP            MOV reg_2, STACK[2] 
72:                            NOP                            NOP               MOV reg_0, reg_4 
73:                            NOP                            NOP               MOV reg_1, reg_2 
74:                            NOP                            NOP             CALL RIGHT 0 UP 74 
75:                            NOP                            NOP                      JUMP BY 9 
76:                            NOP                            NOP            MOV reg_2, MEM[519] 
77:                            NOP                            NOP             MOV reg_5, reg_2+1 
78:                            NOP                            NOP            MOV MEM[519], reg_5 
79:                            NOP                            NOP                  MOV reg_5, 95 
80:                            NOP                            NOP    MOV reg_2, MEM[reg_2+reg_5] 
81:                            NOP                            NOP                   CMP reg_2, 3 
82:                            NOP                            NOP                JUMP BY 2 IF == 
83:                            NOP                            NOP                           LOSE 
84:                            NOP                            NOP                  DROP 4 VALUES 
85:                            NOP                            NOP              RETURN THISFUN 85 
```

Each column is a separate function, and the first one is the main entry.
We rewrote the pseudo-assembly into a more readable forms:

```
left function:
0-16: check if CTF{...}
for var1 in range(0, 80):
  stack[var1+3] = 0

24:
loop
    check if flag inside is in range 43..122 (check charset)
    39:
    check that each character is unique (using that array above)
54:
call middle function
memCNT = 0
v0 = 43
loop until v0 > 122
    r2 = v0
    r5 = 30
    r0 = 35
    r1 = r2
    call right function
    v0++
win

; this function copies the middle of the flag, permuted using a constant
; permutation, to memory cells 35..64 (30 bytes)
middle function:
for v3 in range(0, 30): # For each char of the flag
    r2 = [v3+65] # table of small constants
    [r2+35] = [v3+4] # copy flag[i] somewhere

; some binsearch
right function:
(called with tgt = r1 = 43..122, buf = r0 = 35 (permuted flag), flaglen = r5 = 30)
(r4 clobbered immediately, r2 too, rest is saved in vx)
; tgt constant

if r2 == 424: lose. # Probably assert no buffer overflow.
if flaglen == 0:
    r2 = [95 + CNT++]
    if r2 == 4: return
    lose.
r2 = flaglen-1
r2 += (r2>>31) # always zero??
r2 >>= 1
newindex = r2 # approx flaglen/2
if tgt < [buf+newindex]:
    r2 = [95 + CNT++]
    if r2 != 1: lose.
    r5 = newindex
    r0 = buf
    r1 = tgt
    call right
    return
if tgt > [buf+newindex]:
    r2 = [95 + CNT++]
    if r2 != 2: lose.
    r5 = flaglen-newindex-1
    r0 = newindex+1+buf
    r1 = tgt
    call right
    return
r2 = [95 + CNT++]
if r2 != 3: lose.
```

We found that the first function checks that the flag characters are unique,
calls the second function, and the repeatedly the third one.

The second function permuted the flag characters using a hardcoded permutation
written in m.png pixels `65..94`.

The third function was the longest, and it turns out it implements something similar
to binary search. It asserts at each call what the current comparison result should
be, encoded as a value from 1-4, also hardcoded in m.png pixels starting from 95th.

We wrote a `solve.py` script that uses m.png to simulate the binary search, and saving
the result character if the hardcoded comparison result says equal (i.e. needle found).
Then we used the hardcoded permutation to invert the flag buffer, which resulted in
the correct flag (after wrapping in `CTF{...}`, as the turtles use only the middle:

`CTF{iT5_E-tUr+1es/AlL.7h3;waY:d0Wn}`
