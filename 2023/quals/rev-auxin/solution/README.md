# Google CTF 2023 - RE: Auxin writeup

*Note: this writeup was created by a challenge tester during our internal test run. This writeup is for an earlier version of the challenge with a different puzzle, so addresses may have changed.*

In the challenge we get a ROM for the Uxn virtual machine. There is an emulator for it and when executed, we get a demo-like screen asking us for the flag, then telling us if it’s correct - so a pretty standard crackme setup.

We found a disassembler for the virtual machine: https://github.com/Liorst4/uxn-disassembler
It worked okay, but the disassembly looked very foreign to us. I mean, look at this:

```
|04e6   #00             ( 8000 )
|04e8   SWP             ( 04 )
|04e9   #084e           ( a0084e )
|04ec   ADD2            ( 38 )
|04ed   LDA             ( 14 )
|04ee   #00             ( 8000 )
|04f0   LDZ2            ( 30 )
|04f1   #04             ( 8004 )
|04f3   SFT2            ( 3f )
|04f4   #42             ( 8042 )
|04f6   LDZ             ( 10 )
|04f7   #00             ( 8000 )
|04f9   SWP             ( 04 )
|04fa   SUB2            ( 39 )
|04fb   #0003           ( a00003 )
|04fe   DIV2k           ( bb )
|04ff   MUL2            ( 3a )
|0500   SUB2            ( 39 )
|0501   NIP             ( 03 )
|0502   #05             ( 8005 )
|0504   MUL             ( 1a )
```

Documentation for the machine is quite hard to read, but the most useful pages are:

- https://wiki.xxiivv.com/site/uxntal.html
- (opcodes) `https://wiki.xxiivv.com/site/uxntal_reference.html`
- https://wiki.xxiivv.com/site/uxn.html
- (vectors) https://wiki.xxiivv.com/site/varvara.html


The first part of the code seems to be setting up some vectors:

```
|0100	#0131		( a00131 )
|0103	#06		( 8006 )
|0105	DEO2		( 37 )
|0106	#000b		( a0000b )
|0109	#08		( 8008 )
|010b	DEO2		( 37 )
|010c	#15bf		( a015bf )
|010f	#0a		( 800a )
|0111	DEO2		( 37 )
|0112	#38bf		( a038bf )
|0115	#0c		( 800c )
|0117	DEO2		( 37 )
|0118	#0149		( a00149 )
|011b	#20		( 8020 )
|011d	DEO2		( 37 )
|011e	#052a		( a0052a )
|0121	#80		( 8080 )
|0123	DEO2		( 37 )
|0124	#0200		( a00200 )
|0127	#22		( 8022 )
|0129	DEO2		( 37 )
|012a	#0140		( a00140 )
|012d	#24		( 8024 )
|012f	DEO2		( 37 )
|0130	BRK		( 00 )
```

From the vector docs:

```
System.metadata = 0x131
System.red = 0x000b
System.green = 0x15bf
System.blue = 0x38bf

Screen.vector = 0x0149
Screen.width = 0x0200
Screen.height = 0x0140

Controller.vector = 0x052a
```

At 0x131 we have the string “auxin Google CTF 2023”, so probably the window title.
Not sure what’s with the red/green/blue values, let’s skip them for now. Screen is set to 512x320
with the update routine at 0x149. Finally, at 0x052a we have the controller update routine - probably keyboard input.

The disassembler didn’t support some of the jump instructions, so I had to patch them in.

I started reversing the keyboard service (as the screen routine hopefully only draws the screen and not performs
important flag calculations).

My comments:
```
; 52a: the controller isr
; if [3] > 1 return ; probably [3] is state, good/bad/unchecked
; [3] = 0
; if key == 0x08 goto 571 ; backspace
; if key == 0x0d goto 590 ; newline
; if key < 0x20 return
; if key > 0x7e return
; if [2] > 0x7f return ; [2] is current flag length, max 7f
; [[2] + 0x80] = key ; so flag is stored at 0x80:0xff
; [2]++
; return
; 571: ; backspace
; if [2] == 0 return
; [2]--
; [[2]+0x80] = 0
; return

; 590: ; after newline, check flag
; [3] = 3
; call 78d1
; return

; 78d1:
; [5c7] = 78ea (start from this address)
; [5cb] = 7942 ; end on this address
; [5d4] = da49 ; this is encryption key
; call 5c6
; 78ea: ; start of encrypted code

; 5c6: (decrypt data function)
; if 0 == 0: goto 5f4 ; will be overwritten
; some encryption on the return address? xors, shifts etc.
; let's not reverse this, just dump from emulator
; jump 5c9
; 5f4:
; return
```

So we see data entry functions, with the flag at 0x80, up to 127 characters long. After pressing enter,
a code decryption is performed and execution goes to code at 78ea, initially encrypted. I modified the
emulator code so that it will dump the memory when the program counter reaches 78ea.

The code at 78ea puts `[5f6+i] = flag[i] ^ [7d2f+i]` for i < 0x80, and then decrypts two more code segments:
- 7942-7a01
- 78ea-7942

The second of those is the one we just executed, effectively re-encrypting it.

We decrypted the next segment of code in the same manner, which further decrypted 7a01-7a5d, which
also decrypted further code. At this point we simply patched the emulator to print out the decoded bytes
whenever it ran through the decryption routine.

Code segment at 7942 is a triply-nested loop that mixes flag bytes from 5f6 to 676 in a weird way.
Probably the best way to proceed will be to rewrite this in Z3, cross-checking with the emulator to see
if the transcription gives good intermediate values.

Code segment at 7a01 again xors the flag bytes: `[5f6+i] = 676[i] ^ 7e2f[i]`.

Code segment at 7a5d is a short loop that clears array 676 (apparently to make analysis harder).

Code segment at 7aa8 is again a loop, iterating from 6f6 to 83a (324 iterations) saving the effect
of some calculation to each spot. The calculation appears to be dependent on the value of iterator mod 9,
as though it was some matrix calculation perhaps? The calculation depends on the 5f6 array.

Code segment at 7b38 is a short if: `if [839] == 1: [83a] = 2, else [83a] = 1`.

Code segment at 7b84 iterates from 77d9 to 78d1 (skipping by two, so that’s an array of 124 2-byte words).
It checks if, for each value X from that array the following equality holds: `6f6[X/10]==(X%10)`.
If not, it sets `[83a]=1`. So that 83a is probably some condition variable indicating if we made an error
so far. The 77d9 array, when parsed as `(X/10, X%10)`, shows unique pairs of integers like
`(265, 6) (266, 2) (268, 1) (270, 1)`. Some X/10’s are missing and presumably need to be fixed by the next code segment.

```
2 7 7   22 151 3 
   7  5    3   6 
37 7  2  22  2 72
     4 6     4   
 4  4   5 5      
3    2 12   42   
 9  32 9 3   2 73
 1  4     6    4 
 7 5  6  1 1 8 4 
2 2 1  1  1723 34
 5254446  2   1  
2      2 3   2 5 
  56  99     4 5 
  3   8   7 16 32
4 4 5  2  3 4  3 
 4  4  2 162 1 1 
  6 7 5 93 1  7  
 5   12     4 7 8
1 773       7    
```


Code segment at 7be6 consists of a subroutine and the main thread of code.
The subroutine looks suspiciously like 2D DFS or something like that, as it calls itself with an argument
that is either +/- 1 of the original, or +/- 0x11 of the original. So that suggests a 17x17 maze?
This might make sense, as (surprise!) 18x18 = 324, the number of iterations in one of the previous code chunks.
```
if [7bea] > 10 return ; if component size > 10
if 6f6[ii]&f0 return ; maybe it’s a wall?
if 6f6[ii] != [7be9] return ; if current tile color is wrong
6f6[ii] |= 0x10 ; visited
[7bea]++ ; size++
if ii % 0x11 != 0
	dfs(ii-1)
if ii % 0x11 != 0x10:
	dfs(ii+1)
if ii/0x11 != 0
	dfs(ii-0x11)
if ii/0x11 != 0x12
	dfs(ii+0x11)
```

The main thread of code loops over i < 0x143 (323) and:
- if `6f6[i] & f0`: continues to the next iteration (presumably it’s a wall? Or visited!)
- otherwise, sets `[7be9]=6f6[i], [7bea]=0`, then calls the DFS(i), and finally verifies whether `6f6[i] & 0f == [7bea]` (so it seems like `6f6[i]` holds the component size?)
I think `[7bea]` might be the distance from some location?

Okay, at this point I think I know what this code segment tries to achieve: it’s a 17x19 Fillomino
(I didn’t know the name, just searched for some keywords), a puzzle where you need to fill the
grid with numbers, creating regions containing only one unique digit each, equal to the region size.
There appear to be some solvers for that online? https://www.noq.solutions/fillomino seems to work, but
it doesn’t allow for uploading puzzles - do we really need to fill it manually? Oh, but it does have an API.
But it seems to return some `b'{"message": "\'NoneType\' object has no attribute \'add\'"}'` for this grid...
Oh, it worked, it had a quirk in the API that the coordinates need to be multiplied by two for some reason.
Anyway, here’s the unique solution:
```
22777555223151333
33179556663352662
37779226622552672
44999496551544677
44944499555646677
39933291223642873
39773299933682873
31774444996688843
27755566616128844
27251221631723334
55254446632742155
25888842232742655
25565899997744652
33365888937716632
44465552933246633
54664442916241718
55677455936147788
55773125936647788
17773325536677888
```

And the code that generated it (through an API call):
```
import struct
import requests
import json

b = open("auxin.rom", "rb").read()

stuff = b[0x77d9-0x100:0x78d1-0x100]
s = struct.unpack(">" + "H" * 124, stuff)

dic = {}
for k in s:
  a, b = k//10, k%10
  dic[a//0x11, a%0x11] = b

print("Empty grid:")
for i in range(0x13):
  s = ""
  for j in range(0x11):
    if (i,j) not in dic:
      s += " "
    else:
      s += str(dic[i,j])
  print(s)

grid = {}
for i,j in dic:
  grid["%d,%d" % (i*2+1,j*2+1)] = str(dic[i,j])

puzzle = json.dumps({
    "param_values": {"r": "19", "c": "17"},
    "grid": grid,
    "properties": {"outside": "0000", "border": False}
})

r = requests.get("https://www.noq.solutions/solver", params={"puzzle_type":"fillomino", "puzzle":puzzle})
sol = json.loads(r.content.decode())["1"]
print("Solved grid:")
for i in range(0x13):
  s = ""
  for j in range(0x11):
    s += str(sol["%d,%d" % (i*2+1,j*2+1)])
  print(s)
```

Code segment at 7cf2 clears memory from 6f6 to 83a, sets `[3] = [83a]` and `[83a] = 0`.

Now we can work backwards, to the 7aa8 segment.
```
; i=6f6
; while i < 0x83a
	; X = 0
	; j = 0
	; while2 j < 0x80
		; X = X * 256 + flag[j]
		; flag[j] = X / 9
		; X %= 9
	; [i] = X + 1
```

So in each outer iteration, we go over the whole temporary flag (6f6) and repeatedly divide it by 9
or multiply by 256. Weird? I rewrote the algorithm in Python:
```
def doit(flag):
    for i in range(3):
        X = 0
        for j in range(len(flag)):
            X *= 256
            X += flag[j]
            flag[j] = X // 9
            X %= 9
        print(X)
```
After running it on some examples, I figured out that it is probably translating from base-256 to base-9
numbers! Makes sense, as the data size increases from 128 bytes to 324, or about 2.5x, which is roughly
the ratio of `log2(256)` to `log2(9)`.

7a01 was just a xor loop, trivial to inverse.

Other than the initial xor, we’re left with 7942, which had some triple loop. Let’s take a look again.

```
; while i < 0x80
	j = 0
	; while i+j <= 0x7f
		; [7945:7946] = 7daf[i]*5f6[j]
		; k=i+j
		; while3 k < 0x80
			; [7949:794a] = 676[k]+b[7946]
			; [676+j] = b[794a]
			; [7946] = b[7945]+b[7949]
			; b[7945] = 0
			; if b[7946] == 0: break ; no more carry
```

Now I can see that this is just an implementation of big integer multiplication - it multiplies 128 byte
integers at 7daf (constant) and 5f6 (previous temporary flag), putting the result in 676.

Now we have all the information we need to solve the challenge. I wrote some extra emulator
patches to dump memory at various stages of execution, to debug and compare with my implementation.
Here’s the solver, implementing first the forward pass (as the ROM does), and then the inverse
operations below (to get the real flag):
```
rom = open("auxin.rom", "rb").read()
ram = b"\x00" * 256 + rom

flag = b"abc"
flag += b"\x00" * (128 - len(flag))

# Xor with const.
x5f6 = []
for i, j in zip(flag, ram[0x7d2f:]):
  x5f6.append(i^j)
x5f6 = bytes(x5f6)
print(x5f6.hex())

# Multiply with const.
const = int.from_bytes(ram[0x7daf:][:0x80], "little")
x5f6 = int.from_bytes(x5f6, "little")
mul = x5f6 * const
mul %= 1<<1024
mul = mul.to_bytes(128, "little")
print(mul.hex())

# Xor with const.
x5f6 = []
for i, j in zip(mul, ram[0x7e2f:]):
  x5f6.append(i^j)
x5f6 = bytes(x5f6)
print(x5f6.hex())

# To base-9
x5f6 = int.from_bytes(x5f6, "big")
print(hex(x5f6))
def numberToBase(n, b):
    if n == 0:
        return [0]
    digits = []
    while n:
        digits.append(int(n % b))
        n //= b
    return digits[::-1]
base9 = numberToBase(x5f6, 9)
base9 = "".join([str(i+1) for i in base9][::-1])
print(base9)

print()
print()
print("Now backwards.")
print()
print()

if 1:
  base9 = """22777555223151333
33179556663352662
37779226622552672
44999496551544677
44944499555646677
39933291223642873
39773299933682873
31774444996688843
27755566616128844
27251221631723334
55254446632742155
25888842232742655
25565899997744652
33365888937716632
44465552933246633
54664442916241718
55677455936147788
55773125936647788
17773325536677888
""".replace("\n", "")


# From base-9
base9 = "".join(chr(ord(c)-1) for c in base9)
x5f6 = int(base9[::-1], 9)
x5f6 = x5f6.to_bytes(128, "big")
print(x5f6)

# Xor with const.
mul = []
for i, j in zip(x5f6, ram[0x7e2f:]):
  mul.append(i^j)
mul = bytes(mul)
print(mul.hex())


# Undo multiply with const.
const = int.from_bytes(ram[0x7daf:][:0x80], "little")
mul = int.from_bytes(mul, "little")
x5f6 = mul * pow(const, -1, 1<<1024)
x5f6 %= 1<<1024
x5f6 = x5f6.to_bytes(128, "little")
print(x5f6.hex())

# Xor with const.
flag = []
for i, j in zip(x5f6, ram[0x7d2f:]):
  flag.append(i^j)
flag = bytes(flag)
print(flag)

#b'CTF{C0m3_5Tay_4_Wh1Le_anD_l1S7eN_T0_tH3_Mus1C___}\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

For completeness, I attach the patches.
For uxnemu.c, to dump the decrypted code and intermediate data:
```
diff --git a/src/uxn.c b/src/uxn.c
index a8f80ef..8e1f9d0 100644
--- a/src/uxn.c
+++ b/src/uxn.c
@@ -48,6 +48,26 @@ uxn_eval(Uxn *u, Uint16 pc)
 		k = ins & 0x80 ? 0xff : 0;
 		s = ins & 0x40 ? &u->rst : &u->wst;
 		opc = !(ins & 0x1f) ? (0 - (ins >> 5)) & 0xff : ins & 0x3f;
+		static int decoded[1<<16];
+                if (pc - 1 == 0x5f5) { /*end of decryption*/
+                  int start = ram[0x5c7] * 256 + ram[0x5c8];
+                  int end = ram[0x5cb] * 256 + ram[0x5cc];
+                  if (!decoded[start]) {
+					  printf("Decryption data (from 5f6 to 83a):\n");
+					  int j;
+					  for (j = 0x5f6; j <= 0x83a; j++) {
+						printf("%02x ", ram[j]);
+					  }
+					  printf("\n");
+                    decoded[start] = 1;
+                    printf("Now we'll execute decrypted code at %04x:\n", start);
+                    int i;
+                    for (i = start; i <= end; i++) {
+                      printf("%02x ", ram[i]);
+                    }
+                    printf("\n");
+                  }
+                }
 		switch(opc) {
 			/* IMM */
 			case 0x00: /* BRK   */ return 1;
```

And for the uxn-disassembler, to add rudimentary support for jump opcodes:
```
diff --git a/uxn_disassembler.py b/uxn_disassembler.py
index 4967812..a04ef68 100755
--- a/uxn_disassembler.py
+++ b/uxn_disassembler.py
@@ -114,8 +114,19 @@ def disassemble(rom: bytes) -> typing.Generator[str, None, None]:
                     and i + 1 >= len(rom)
                 )
         ):
-            line += f'{rom[i]:02x}'
-            i += 1
+            delta = rom[i+1] * 256 + rom[i+2]
+            real = i + delta + 0x100 + 3
+            real &= 0xffff
+            line += "(" + rom[i:i+3].hex() + ")"
+            if instruction == 0x20:
+                line += "JUMP CONDITIONAL 0x%04x" % real
+            elif instruction == 0x40:
+                line += "JUMPINSTANT 0x%04x" % real
+            elif instruction == 0x60:
+                line += "CALL 0x%04x" % real
+            else:
+                raise Exception()
+            i += 3
         elif short_mode:
             line += f'{lit_prefix}{rom[i+1]:02x}'
             line += f'{rom[i+2]:02x}{lit_postfix}'
```


