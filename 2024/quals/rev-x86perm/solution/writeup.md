**Solving the x86perm**

We have around 10kB of encrypted code. So around 40 instances of each byte, assuming they are distributed evenly. It should be possible to reverse engineer quite a few bytes.

We instantly see that most of the functions (we have symbols!) have similar prolog and epilogue.

Prologues from 4 functions:


```
5c 5c 5c 5c push rbp? [55]
9f 9f 9f 9f mov rbp, rsp? [48]
dd dd dd dd    [89]
4c 4c 4c 4c    [e5]
86 dd 9f 9f   the latter two: [48] - i.e. extended opcode
fe a1 c6 39
fe d5 78 78
fe 9b 54 3e
fe bc e1 9f
8a d5 fe dd
60 9f fe a1
bd 9a 9f 8a
fe 04 dd 9f
fe 9f f3 86
d4 33 9f 81
cc 88 ec cb
b1 dd 15 0b
```


Epilogues are fairly short:


```
fe 48 dd 15
d4 30 04 15
cc cc cc 2d leave? [c9]
b1 b1 b1 b1 ret? [c3]
```


```
λ (echo 'BITS 64'; echo 'pop rbp') > test.s; nasm test.s -o test; hexdump -C test
```

```
λ echo '0: 48 b8 90 90 90 90 90 90 90 90' | xxd -r | ndisasm -b 64 -
```

These bytes look legit, the 48 (rex.W) in particular seems to work as instruction boundaries?

I also dumped the most common bytes, and it seems they are:


```
0x9f 1268 0x48 rex.W
0x15 1265 ?
0xfe 812 ?
0xdd 625 0x89 mov ?, ?
0x3e 490 ?
0x10 306 ?
0xbc 243 ?
0x86 240 ?
0x9b 199 ?
0x21 188 ?
0xec 157 ?
0xcb 155 ?
```


For comparison, /bin/ls has:


```
0x0 11976
0xff 5339
0x48 5295
0xf 3578
0x89 2901
0x1 2036
0x8b 1924
0x24 1885
0x83 1494
0xe8 1400
```


What about longer sequences?


```
['0x15', '0x15'] 694 ['?', '?']
['0x9f', '0xdd'] 536 ['0x48', '0x89']
['0xfe', '0xfe'] 468 ['?', '?']
['0x15', '0x9f'] 405 ['?', '0x48']
['0x9f', '0x86'] 159 ['0x48', '?']
['0xec', '0x15'] 157 ['?', '?']
['0xfe', '0x9f'] 156 ['?', '0x48']
['0x9f', '0x58'] 137 ['0x48', '?']
['0xdd', '0x10'] 124 ['0x89', '?']
['0x9f', '0x4e'] 123 ['0x48', '?']
['0xdd', '0x1b'] 113 ['0x89', '?']
['0x9f', '0x9b'] 107 ['0x48', '?']
['0xdd', '0x21'] 107 ['0x89', '?']
['0x3e', '0x3e'] 74 ['?', '?']
['0xfe', '0x8a'] 69 ['?', '?']
['0xdd', '0xbc'] 68 ['0x89', '?']
['0xe1', '0xfe'] 67 ['?', '?']
['0x86', '0xfe'] 66 ['?', '?']
['0x58', '0x10'] 65 ['?', '?']
['0x21', '0x86'] 65 ['?', '?']
['0xcb', '0xb'] 64 ['?', '?']
['0x9b', '0x10'] 61 ['?', '?']
['0x4', '0x9f'] 58 ['?', '0x48']
['0x9b', '0xbc'] 57 ['?', '?']
['0x3e', '0x9f'] 56 ['?', '0x48']
['0xe2', '0xfe'] 56 ['?', '?']
['0xb4', '0x15'] 55 ['?', '?']
['0x21', '0xbc'] 48 ['?', '?']
['0x9f', '0xf6'] 42 ['0x48', '?']
['0x21', '0x8a'] 40 ['?', '?']
```


vs. for /bin/ls:


```
['0x0', '0x0'] 6552
['0xff', '0xff'] 2427
['0x48', '0x89'] 1484
['0x1', '0x0'] 1253
['0x0', '0x48'] 1225
['0x48', '0x8b'] 1061
['0xf', '0x1f'] 880
['0xff', '0x48'] 674
['0x48', '0x83'] 659
['0x48', '0x8d'] 622
['0x44', '0x24'] 598
['0x4c', '0x89'] 538
['0x0', '0xf'] 468
['0xf', '0x84'] 467
['0xfe', '0xff'] 428
['0xf', '0xb6'] 426
['0x2', '0x0'] 374
['0x85', '0xc0'] 364
['0x48', '0x85'] 361
['0xf', '0x85'] 328
['0x0', '0xe8'] 301
['0xc0', '0xf'] 301
['0xff', '0xf'] 288
['0xf3', '0xf'] 287
['0x49', '0x89'] 287
['0x66', '0xf'] 286
['0x4c', '0x8b'] 258
['0x0', '0x31'] 257
['0x84', '0x0'] 256
['0x1f', '0x84'] 252
```


So it seems 0x15 and 0xfe are 0xff and 0x00 respectively (they are very common and often come in pairs, with 0x00 repeated 4 times being more common than 0xff).

```
['0x86', '0xfe', '0xfe', '0xfe'] 66 ['?', '0x0', '0x0', '0x0']
```

suggests 0x86 might be 0x01?

Most common after 0x48 (other than 0x89)

In our binary:

0x86, 0x58, 0x4e, 0x9b, and maybe 0xf6

In grep:

0x8b, 0x83, 0x8d, 0x85 (mov, cmp, lea, test)

Quite likely these four bytes correspond to each other, maybe in another order.

```
['0x3e', '0x3e'] 74 ['?', '?']
```

This is very odd. In normal binaries, the only repeated two bytes are usually 0x00 and 0xff - and here we have another! This is also the 5th most common byte, so very common! However the repeats only occur in the &lt;game> function, which also has other weird repeats: a0 (8 times in a row), a5 (3 times in a row), e3 (3 times in a row), f9 (3 times in a row). In fact, these seem to be close to each other too, e.g. a0 3e 3e a5 a5 a5 3e 3e 48. It seems these might be constants being loaded to a register? In that case let's see what's just before these bytes - that might be the mov reg, imm64 instruction!

```
[48] 99

[48] 17

[48] 86

[48] 4e
```

These appear to be related addresses:


```
at 0x3df3: 9f dd 10 3a ec 15 15 9f dd 1b 4b ec 15 15
trans:     48 89 ?? ?? ?? ff ff 48 89 ?? ?? ?? ff ff
at 0x3e15: 9f dd f2 fe 15 15 15 9f dd f3 30 15 15 15
trans:     48 89 ?? 00 ff ff ff 48 89 ?? ?? ff ff ff
at 0x3e37: 9f dd f2 ae 15 15 15 9f dd f3 e0 15 15 15
trans:     48 89 ?? ?? ff ff ff 48 89 ?? ?? ff ff ff
at 0x3e59: 9f dd f2 3e 15 15 15 9f dd f3 5b 15 15 15
trans:     48 89 ?? ?? ff ff ff 48 89 ?? ?? ff ff ff
at 0x3e7b: 9f dd f2 25 15 15 15 9f dd f3 80 15 15 15
trans:     48 89 ?? ?? ff ff ff 48 89 ?? ?? ff ff ff
at 0x3e9d: 9f dd f2 26 15 15 15 9f dd f3 9f 15 15 15
trans:     48 89 ?? ?? ff ff ff 48 89 ?? 48 ff ff ff
at 0x3ebf: 9f dd f2 b5 15 15 15 9f dd f3 37 15 15 15
trans:     48 89 ?? ?? ff ff ff 48 89 ?? ?? ff ff ff
at 0x3ee1: 9f dd f2 14 15 15 15 9f dd f3 02 15 15 15
trans:     48 89 ?? ?? ff ff ff 48 89 ?? ?? ff ff ff
           9f dd f2 52 15 15 15 9f dd f3 ac 15 15 15
           48 89 ?? ?? ff ff ff 48 89 ?? ?? ff ff ff
3f11:      9f dd 0b 44 9f dd a1 d8
           48 89 ?? ?? 48 89 ?? ??
                 0b d4       a1 06       0b 7e       a1 93
           48 89       48 89       48 89       48 89
3f51:            0b 09       a1 86
           48 89       48 89
3f6d:            0b 54       a1 f1
           48 89       48 89
3f89:            0b 04       a1 f7
           48 89       48 89

We may conjecture that these addresses form arithmetic sequence, so these encrypted bytes are actually an arithmetic sequence (and 0xec probably translates to 0xfe):

3a fe=[00] ae 3e 25 26      b5 14 52   44 d4  7e? 09 54 04
4b 30      e0 5b 80 9f=[48] 37 02 ac   d8 06? 93  86 f1 f7

This appears to be a sequence incrementing by 8 (first row, second row, first row, second row, ...). Then the last byte (86 encrypted) would decrypt to b8. We already saw [48] 86, which would now decrypt to [48] [b8], or mov rax, imm64 - sounds good in this context!

This seems to be code like:
    112d:	48 b8 61 62 63 64 65 	movabs rax,0x6867666564636261
    1134:	66 67 68 
    1137:	48 ba 69 6a 6b 6c 6d 	movabs rdx,0x706f6e6d6c6b6a69
    113e:	6e 6f 70 
    1141:	48 89 45 e0          	mov    QWORD PTR [rbp-0x20],rax
    1145:	48 89 55 e8          	mov    QWORD PTR [rbp-0x18],rdx

compiled from 
	char somestr[] = "abcdefghijklmnopqrstuvwxyz";
```


from the above code pattern we know:


```
3de9: [48] 4e imm64 - should be [48] [ba] imm64
3df3: [48] [89] 10 [f0] - should be [48] [89] [45] [f0]
3dfa: [48] [89] 1b [f8] - should be [48] [89] [55] [f8]
```


ugh, maybe that's too much assumption - the 10->45 can very likely stay, but the other instruction pair can use different register (we see that in later part of that function)

but even now we run into an issue:


```
    3df3:       48 89 45 f0             mov    QWORD PTR [rbp-0x10],rax
    3df7:       cc                      int3
    3df8:       ff                      (bad)
    3df9:       ff
```


After that snippet we have the next mov that we're reasonably certain it's correct. So the XX ff ff is either a single instruction (as ff or ff ff are not valid), or it should be part of the previous instruction - which is more likely. Then it would still be mov [rbp-XX], rax; however the XX would be imm32 and not imm8.


```
λ (echo 'BITS 64'; echo 'mov [rbp-0x12345678], rax') > test.s; nasm test.s -o test; hexdump -C test
00000000  48 89 85 88 a9 cb ed                              |H......|
```


So that byte is not 45, it's 85 instead.


```
0000000000003dcd <game>:
    3dcd:       55                      push   rbp
    3dce:       48 89 e5                mov    rbp,rsp
    3dd1:       48 cc                   rex.W int3
    3dd3:       cc                      int3
    3dd4:       b0 cc                   mov    al,0xcc
    3dd6:       00 00
```


This prolog seems to include sub rsp, imm32:


```
λ (echo 'BITS 64'; echo 'sub rsp, 0x3040') > test.s; nasm test.s -o test; hexdump -C test
00000000  48 81 ec 40 30 00 00                              |H..@0..|
00000007
```


c6 78 -> [81] [ec]

The next part of the prolog:


```
3dd8:       48 89 cc                mov    rsp,rcx
3ddb:       58                      pop    rax
    3ddc:       cc                      int3
    3ddd:       ff                      (bad)
    3dde:       ff
```


this cannot be two or three instructions, as no splitting makes sense. Brute forcing the first unknown byte we see only one reasonable candidate: 


```
00000000  4889BD58CCFFFF    mov [rbp-0x33a8],rdi
```


so we have:

f3 -> [bd]

snippet 1:


```
   3cc8:       88 48 b8                mov    BYTE PTR [rax-0x48],cl
    3ccb:       cc                      int3
    3ccc:       cc                      int3
    3ccd:       cc                      int3
    3cce:       20 cc                   and    ah,cl
    3cd0:       90                      nop
    3cd1:       cc                      int3
    3cd2:       20 48 cc                and    BYTE PTR [rax-0x34],cl
    3cd5:       cc                      int3
    3cd6:       cc                      int3
    3cd7:       20 cc                   and    ah,cl
    3cd9:       68 cc 20 90 48          push   0x489020cc
    3cde:       89 cc                   mov    esp,ecx
    3ce0:       90                      nop
    3ce1:       48 89 55 98             mov    QWORD PTR [rbp-0x68],rdx
```


this looks like:


```
db 0x88
00000000  48B8484746454443  mov rax,0x4142434445464748
         -4241
0000000A  48BA494847464544  mov rdx,0x4243444546474849
         -4342
00000014  488945A0          mov [rbp-0x60],rax
00000018  48895598          mov [rbp-0x68],rdx
```


this time we know the correct registers

so:

4e -> ba (After all correct, so 1b: 55 should be too)

bc -> 45

snippet 2:


```
0000000000003cbd <generic>:
    3cbd:       55                      push   rbp
    3cbe:       48 89 e5                mov    rbp,rsp
    3cc1:       48 cc                   rex.W int3
    3cc3:       cc                      int3
    3cc4:       80 48 89 cc             or     BYTE PTR [rax-0x77],0xcc
    3cc8:       88
```


this looks like saving registers:


```
00000000  48897D80          mov [rbp-0x80],rdi
00000000  48897588          mov [rbp-0x78],rsi
```


but the top line needs two bytes, so this is wrong, hmmm. nevermind then

this starts to look pretty good:


```
32db:       48 b8 cc cc cc cc cc    movabs rax,0xcccccccccccccccc
    32e2:       cc cc cc 
    32e5:       48 ba cc cc cc cc 20    movabs rdx,0xcccccc20cccccccc
    32ec:       cc cc cc 
    32ef:       48 89 45 a0             mov    QWORD PTR [rbp-0x60],rax
    32f3:       48 89 55 a8             mov    QWORD PTR [rbp-0x58],rdx
    32f7:       48 b8 cc 45 cc cc 20    movabs rax,0xcccccc20cccc45cc
    32fe:       cc cc cc 
    3301:       48 ba cc cc 48 cc 20    movabs rdx,0xcccccc20cc48cccc
    3308:       cc cc cc 
    330b:       48 89 45 b0             mov    QWORD PTR [rbp-0x50],rax
    330f:       48 89 55 b8             mov    QWORD PTR [rbp-0x48],rdx
    3313:       48 b8 48 50 cc 20 cc    movabs rax,0xcccccccc20cc5048
    331a:       cc cc cc 
    331d:       48 ba cc cc cc cc 20    movabs rdx,0xcccccc20cccccccc
    3324:       cc cc cc 
    3327:       48 89 45 c0             mov    QWORD PTR [rbp-0x40],rax
    332b:       48 89 55 c8             mov    QWORD PTR [rbp-0x38],rdx
    332f:       48 b8 cc cc cc 45 cc    movabs rax,0x30cc20cc45cccccc
    3336:       20 cc 30 
    3339:       48 ba cc cc cc cc 30    movabs rdx,0xcccccc30cccccccc
    3340:       cc cc cc 
    3343:       48 89 45 d0             mov    QWORD PTR [rbp-0x30],rax
    3347:       48 89 55 d8             mov    QWORD PTR [rbp-0x28],rdx
    334b:       48 b8 cc cc cc cc cc    movabs rax,0xcccccccccccccc
    3352:       cc cc 00 
    3355:       48 89 45 cc             mov    QWORD PTR [rbp-0x34],rax
```


this is from &lt;status> function, so this might be printing some string? In the constants we see a few 0x20's (spaces), as well as "HP" (which could be due to the RPG setting).

<fight> prolog:


```
00000000000033d1 <fight>:
    33d1:       55                      push   rbp
    33d2:       48 89 e5                mov    rbp,rsp
    33d5:       48 81 ec 10 cc 00 00    sub    rsp,0xcc10
    33dc:       48 89 bd f8 cc ff ff    mov    QWORD PTR [rbp-0x3308],rdi
    33e3:       cc                      int3
    33e4:       c8 cc ff ff             enter  0xffcc,0xff
```


the corresponding epilogue would restore something, and rdi from the same address. And we do see something similar, though not exactly the same. I can't reverse engineer that :/

    25db:       48 89 55 58             mov    QWORD PTR [rbp+0x58],rdx

    25df:       cc                      int3

    25e0:       ff                      (bad)

    25e1:       ff 

this seems wrong, it should be [rbp+imm32], so [55] should be actually [95]. After changing that, the imm loading sections look more clear


```
    2072:       48 89 bd 48 cc ff ff    mov    QWORD PTR [rbp-0x33b8],rdi
    2079:       48 89 cc                mov    rsp,rcx
    207c:       40 cc                   rex int3
    207e:       ff                      (bad)
    207f:       ff
```


this is &lt;go> prolog ^

it looks like the second instructions should save rsi register on stack:

00000000  4889B540CCFFFF    mov [rbp-0x33c0],rsi

so:

f2 -> b5

    3e01:       48 cc                   rex.W int3

    3e03:       90                      nop

    3e04:       20 20                   and    BYTE PTR [rax],ah

    3e06:       90                      nop

    3e07:       90                      nop

    3e08:       90                      nop

    3e09:       20 20                   and    BYTE PTR [rax],ah

    3e0b:       48 cc                   rex.W int3

    3e0d:       20 90 90 90 90 90       and    BYTE PTR [rax-0x6f6f6f70],dl

    3e13:       90                      nop

    3e14:       00 48 89                add    BYTE PTR [rax-0x77],cl

    3e17:       b5 00                   mov    ch,0x0

    3e19:       ff                      (bad)

    3e1a:       ff                      (bad)

    3e1b:       ff 48 89                dec    DWORD PTR [rax-0x77]

    3e1e:       bd 08 ff ff ff          mov    ebp,0xffffff08

is definitely:

movabs rsi,

movabs rdi,

mov [], rsi

mov [], rdi

so:

17 -> be

99 -> bf


```
    3ecd:       48 be 90 20 20 20 20    movabs rsi,0x2020202020202090
    3ed4:       20 20 20 
    3ed7:       48 bf 20 20 20 20 90    movabs rdi,0x90209020202020
    3ede:       20 90 00 
    3ee1:       48 89 b5 60 ff ff ff    mov    QWORD PTR [rbp-0xa0],rsi
    3ee8:       48 89 bd 68 ff ff ff    mov    QWORD PTR [rbp-0x98],rdi
    3eef:       48 89 b5 70 ff ff ff    mov    QWORD PTR [rbp-0x90],rsi
    3ef6:       48 89 bd 78 ff ff ff    mov    QWORD PTR [rbp-0x88],rdi
    3efd:       48 be 90 20 20 20 20    movabs rsi,0x2020202020202090
    3f04:       20 20 20 
    3f07:       48 bf 20 20 20 90 90    movabs rdi,0x90209090202020
    3f0e:       20 90 00 
    3f11:       48 89 cc                mov    rsp,rcx
    3f14:       80 48 89 cc             or     BYTE PTR [rax-0x77],0xcc
    3f18:       88 48 be                mov    BYTE PTR [rax-0x42],cl
    3f1b:       90                      nop
```


These bytes look like the short (imm8) version of the mov [rbp-imm8], rdi/rsi.

0b -> 75

a1 -> 7d


```
    249b:       48 b8 cc cc 75 20 cc    movabs rax,0xcc20cccc2075cccc
    24a2:       cc 20 cc 
    24a5:       48 ba cc cc cc cc cc    movabs rdx,0xcccccccccccccc
    24ac:       cc cc 00 
    24af:       48 89 45 f0             mov    QWORD PTR [rbp-0x10],rax
    24b3:       48 89 55 f8             mov    QWORD PTR [rbp-0x8],rdx
    24b7:       48 cc                   rex.W int3
    24b9:       45                      rex.RB
    24ba:       f0 48 89 cc             lock mov rsp,rcx
```


This might be lea rax, [rbp-0x10] for printing the string?

00000000  488D45F0          lea rax,[rbp-0x10]

so:

58 -> 8d

maybe the next instruction would be

00000000  4889C7            mov rdi,rax

21->c7

 2493:       48 cc                   rex.W int3

    2495:       ec                      in     al,dx

    2496:       20

is sub rsp, 0x20

so:

39 -> 83

Let's look for the call instruction. This should be near the movabs stuff?

    2134:       8a 49 64                mov    cl,BYTE PTR [rcx+0x64]

    2137:       ff                      (bad)

    2138:       ff

    2386:       8a 3c ec                mov    bh,BYTE PTR [rsp+rbp\*8]

    2389:       ff                      (bad)

    238a:       ff

Yep, looks like 8a might be call (e8)

    2313:       e8 38 cc ff ff          call   ffffffffffffef50 &lt;_end+0xffffffffffff7ef0>

it's evidently the call to

0000000000001050 &lt;printf@plt>:

so the unknown byte must be 94 -> ed


```
    4a83:       48 8d 95 90 cc ff ff    lea    rdx,[rbp-0x3370]
    4a8a:       48 8d 85 cc cc ff ff    lea    rax,[rbp-0x3334]
    4a91:       48 89 cc                mov    rsp,rcx
    4a94:       48 89 c7                mov    rdi,rax
    4a97:       b8 00 00 00 00          mov    eax,0x0
    4a9c:       e8 cc cc ff ff          call   176d <main+0x5b4>
```


this is likely setting rsi (mov rsi, rdx)

00000000  4889D6            mov rsi,rdx

so:

24 -> d6

NB: https://stackoverflow.com/questions/6212665/why-is-eax-zeroed-before-a-call-to-printf

looks like eax is indeed set to zero before printf or scanf

    4a9c:       e8 cc cc ff ff          call   176d &lt;main+0x5b4>

so this is very likely printf too

    4a15:       e8 cc cc ff ff          call   16e6 &lt;main+0x52d>

this too

    4971:       e8 cc c6 ff ff          call   1042 &lt;puts@plt+0x2>

this too


```
    489c:       48 89 c6                mov    rsi,rax
    489f:       48 8d                   lea    rcx,(bad)
    48a1:       cc                      int3
    48a2:       cc                      int3
    48a3:       cc                      int3
    48a4:       00 00                   add    BYTE PTR [rax],al
    48a6:       48 89 c7                mov    rdi,rax
    48a9:       b8 00 00 00 00          mov    eax,0x0
    48ae:       e8 ed c7 ff ff          call   10a0 <__isoc99_scanf@plt>
```


oh, we got a first complete scanf call, now we know how that looks like

    488a:       e8 cc c7 ff ff          call   105b &lt;printf@plt+0xb>

printf

    48f5:       e8 cc c7 ff ff          call   10c6 &lt;__cxa_finalize@plt+0x6>

printf

    47a7:       e8 cc c8 ff ff          call   1078 &lt;strcmp@plt+0x8>

printf

    46f6:       e8 55 cc ff ff          call   1350 &lt;main+0x197>

printf

    469e:       e8 cc c9 ff ff          call   106f &lt;memset@plt+0xf>

printf

    45a8:       e8 10 cc ff ff          call   11bd &lt;main+0x4>

generic

    44c2:       e8 a0 cc ff ff          call   1167 &lt;register_tm_clones+0x37>

go

    44a9:       e8 38 cc ff ff          call   10e6 &lt;_start+0x16>

shop

    4486:       e8 c5 cc ff ff          call   1150 &lt;register_tm_clones+0x20>

printf

    4315:       e8 36 cc ff ff          call   f50 &lt;__abi_tag+0xbd4>

printf

    40c8:       e8 83 cc ff ff          call   d50 &lt;__abi_tag+0x9d4>

printf

    3db9:       e8 cc cc ff ff          call   a8a &lt;__abi_tag+0x70e>

printf

    3d4c:       e8 ff cc ff ff          call   a50 &lt;__abi_tag+0x6d4>

printf

    3bd2:       e8 cc cc ff ff          call   8a3 &lt;__abi_tag+0x527>

printf

    3ae8:       e8 cc cc ff ff          call   7b9 &lt;__abi_tag+0x43d>

printf

    3a47:       e8 cc d6 ff ff          call   1118 &lt;deregister_tm_clones+0x18>

printf

    3958:       e8 cc d6 ff ff          call   1029 &lt;_init+0x29>

printf

    38b7:       e8 cc cc ff ff          call   588 &lt;__abi_tag+0x20c>

printf

    3697:       e8 cc cc ff ff          call   368 &lt;__abi_tag-0x14>

printf

    4aab:       e8 cc f3 ff ff          call   3e7c &lt;game+0xaf>

game 0000000000003dcd &lt;game>:

    4995:       e8 cc c7 ff ff          call   1166 &lt;register_tm_clones+0x36>

scanf

    4919:       e8 cc c7 ff ff          call   10ea &lt;_start+0x1a>

scanf

    45c1:       e8 cc da ff ff          call   2092 &lt;go+0x2b>

go

    4594:       e8 cc da ff ff          call   2065 &lt;minute+0x2d>

go

    4549:       e8 cc db ff ff          call   211a &lt;go+0xb3>

go

    451c:       e8 cc db ff ff          call   20ed &lt;go+0x86>

go

    44ef:       e8 cc db ff ff          call   20c0 &lt;go+0x59>

go

    4064:       48 89 95 f8 cc ff ff    mov    QWORD PTR [rbp-0x3308],rdx

should be -0x208 so b4 -> fd

    3365:       e8 cc ec ff ff          call   2036 &lt;hour+0x25>

minute

    32ad:       e8 cc cc ff ff          call   ffffffffffffff7e &lt;_end+0xffffffffffff8f1e>

printf

    3261:       e8 cc cc ff ff          call   ffffffffffffff32 &lt;_end+0xffffffffffff8ed2>

printf

    3151:       e8 cc cc ff ff          call   fffffffffffffe22 &lt;_end+0xffffffff

printf

    30fc:       e8 cc cc ff ff          call   fffffffffffffdcd &lt;_end+0xffffffff

printf

    30db:       e8 70 cc ff ff          call   fffffffffffffd50 &lt;_end+0xffffffff

printf

    3097:       e8 b4 cc ff ff          call   fffffffffffffd50 &lt;_end+0xffffffff

printf

    2d84:       e8 c7 cc ff ff          call   fffffffffffffa50 &lt;_end+0xffffffff

printf

    2d3b:       e8 10 cc ff ff          call   fffffffffffff950 &lt;_end+0xffffffff

printf

    2c31:       e8 cc cc ff ff          call   fffffffffffff902 &lt;_end+0xffffffff

printf

    2bc5:       e8 cc cc ff ff          call   fffffffffffff896 &lt;_end+0xffffffff

printf

    2b2f:       e8 cc e5 ff ff          call   1100 &lt;deregister_tm_clones>

printf

    2a0a:       e8 cc cc ff ff          call   fffffffffffff6db &lt;_end+0xffffffff

printf

    290c:       e8 cc cc ff ff          call   fffffffffffff5dd &lt;_end+0xffffffff

printf

    2866:       e8 e5 cc ff ff          call   fffffffffffff550 &lt;_end+0xffffffff

printf

    2749:       e8 cc cc ff ff          call   fffffffffffff41a &lt;_end+0xffffffff

printf

    25bb:       e8 90 cc ff ff          call   fffffffffffff250 &lt;_end+0xffffffff

printf

    24c3:       e8 88 cc ff ff          call   fffffffffffff150 &lt;_end+0xffffffff

printf

    247d:       e8 cc cc ff ff          call   fffffffffffff14e &lt;_end+0xffffffff

printf

    245c:       e8 cc cc ff ff          call   fffffffffffff12d &lt;_end+0xffffffff

printf

    224c:       e8 cc cc ff ff          call   ffffffffffffef1d &lt;_end+0xffffffff

strcmp

    2224:       e8 cc cc ff ff          call   ffffffffffffeef5 &lt;_end+0xffffffff

strcmp

    21fc:       e8 cc cc ff ff          call   ffffffffffffeecd &lt;_end+0xffffffff

strcmp

    2134:       e8 cc cc ff ff          call   ffffffffffffee05 &lt;_end+0xffffffff

printf

    2152:       e8 cc cc ff ff          call   ffffffffffffee23 &lt;_end+0xffffffff

scanf

at this point we can almost start to guess the ascii strings


```
b' `o `o? ``O``H ``OU`H ``E`` `EA`A`` `\x19`VE``O```\x00`O``H\x00\x00\x00`OU`H\x00\x00\x00\x19`VE``O``h`````\x00`ou `oo` `` you`u` ``c`p`c`````\x00``` `s`\x00\x19``s ``p``p`y``\x00`ou `o ``c`````\x00`ou ```` ```o ` ```y shop` A ``` ``h``` `h` cou```` sho`s you so`` ````s `o` s```H`y `s` `o`` ```` `o s``` Ho` cc`` \x19 h``p y`?`\x00``` `s ( (`````\x00`o you ```` `o `uy so```h```` o` EX\x19`?`\x00`ou ````` ou```\x00`h```s `oo `xp```s`````\x00`ou ``````y h````` ````\x00h` ````\x00`` `` `o``` s``` `h`` h` h`````\x00`ou``` `` ` s```` ```````` `h``` ``` o``y ` coup`` `u``````s `h````````\x00`ou ````` o` ``ch`s ``` ````s `` `h` ```p````` `h`` you ```` up``ou` h````h `s ``s`o```` \x19` `s `o` ```h` o`c`oc``ou ````` ````s` `ou s`` ````o` ``````s so````` ```h p`o````s `o ```` c`yp`o`o```h`` `o you `o? o? ``\x19`E `EX\x19``\x00```us\x00\x00\x00````s\x00\x00\x00``````` `o`u`o\x00\x00`h`` `s `` `s ```h` ``oc` o` `oc` sh`````s` you  ```` `` `o````\x00`op``````ou ````` ` ``````` ```s ```y ```p ``` ``s`` you c```o` s``` `c`c`oss``\x00`ou` `o`` `o``s  ``````\x00````us``A``` ````EF` ````GH` ```HP` ```GO``` ````\x19`E` `0````0``````````\x00E```y` ` `` HP`\x00`ou p`ss ou`` `h`` you ```` up` ```s ``````y `h` ``x` ``y` `ou ``` p``````ss ``` h``` `o`h``` `` you` poc```s``\x00\x19``U```\x00`ou ```  ```y``\x00`ou ``y `o `u` ```y `u` `h` `````` c``ch`s up ``s up ```h you``\x00 `you` ``` `s so ``` you `ou````` h`` ` `````` `h` `````` `us` ``u`hs `` ``c```\x00`ou `cc````````y ```p ``` ``ss you` oppo``u```y ``y `o ````c```\x00`h` `````` co```ps`s` `ou `u`c``y `oo` ``ou`` ``` s`` `o`o`y` `h`` ```` `h``` s` s`c` o` `o````\x00`h` `````` h``s you ```h ` ``s```ou ``` `` `h` `````` o` ` ````` `````` ```` ```ss `s ````y`h```A `````` ```ush`` you``\x00```````````````\x00`  ```   ``````\x00`  ````   `````\x00`  ``H`    ````\x00`   ```    ````\x00`          ````\x00`           ```\x00`           ` `\x00`          `` `\x00`          `  `\x00`        ```  `\x00`      ```   ``\x00`      `  ` ```\x00`ou ```` ```y s```py``` `ou ``` `o`` o` `h` ``ou`` ``` ``y `o s```p u```` `o```` `h`` you` ``s```y `s `o` `` `h`s ````c``o```` ``s```s` you``` `````` you``` ``` `os`` `` `ou `o ``c```\x00Uhh` \x19 `h``` so```h```s ``o````````co`` `o ou` ````s` `u```o` c````````\x00F``s`` `h`` `s y `s you` ````?`\x00s ``s````u`` you` s````  s```` po```s``\x00`ou h``` `0 po```s` sp``` ```o ````c`` `````s` ```` `ou`h``ss``\x00`h`` `s you` ``````c`?`\x00`h`` `s you` ``````s`?`\x00`h`` `s you` `ouou` `ou`h``ss?`\x00`o``` ``y `o ch`ch`````\x00O`` `s``` `h` ``h` ```` `s o```\x00'
```


oppo``u```y -> opportunity

`on`t try to ch`ch``t`` -> Don't try to cheat

`ou ha`e `0 points` sp`it into attac`` `e`ense aan` tou`hness -> You have x0 points, split into attack, defense and toughness

With these guesses we have:


```
b" to do? ``O``H ``OU`H ``E`` `EA`A`` `\x19`VE``O`Y`\x00`O``H\x00\x00\x00`OU`H\x00\x00\x00\x19`VE``O`there``\x00You look in yourur `ackpack````\x00\x19t's e`pe`pty``\x00You go `ack````\x00You `alk into a tiny shop` A `an `ehind the counter sho`s you so`e ite`s for sal'Hey `s, long ti`e no see` Ho` ccan \x19 help ya?'\x00`d` `s ( (``d``\x00Do you `ant to `uy so`ething, or EX\x19`?`\x00You `alkk out``\x00`hat's too expennsive``\x00ady haveve it``\x00ht it``\x00id `e don't sell that he here``\x00You're in a s`all village` `here are only a couple `uildings theere````\x00You drea` of riches and flags in the te`ple``` `hen you `ake up`Your health is restored` \x19t is no` eight o'clockYou enter `ines` You see fello` d`arves solving `ath pro`le`s to `ine cryptogold`hat do you do? o? ``\x19`E `EX\x19``\x00`inus\x00\x00\x00ti`es\x00\x00\x00divided `odulo\x00\x00`hat is `d `s `d`he `lock of rock shatters` you  gain `d gold``\x00`ope````You enter a rivei`e it's very deep and fast` you cannot s`i` acrcross``\x00Your `oat `orks  `ell``\x00`tatus``A``` `d`DEF` `d``GH` `d`HP` `d`GO`D` `d``\x19`E` `0`d``0`d````````\x00Ene`y` ` `d HP`\x00You pass out` `hen you `ake up, it's already the next day` You are penniless and have nothing in your pockets``\x00\x19``U```\x00You ran  a`ay``\x00You try to run a`ay `ut the `andit catches up `is up `ith you``\x00 'your ai` is so `ad you `ouldn't hit a tree'` `he `andit `ust laughs `a `ack``\x00You accidentally trip and `iss your opportunity ity to attack``\x00`he `andit collapses` You `uickly look around and see no`ody, then take their sa sack of gold``\x00`he `andit hits you `ith a fist`You are in the `iddle of a large field` `all grass is every`hereA `andit a``ushed you``\x00```````````````\x00`  vvv   ``````\x00`  v`vv   `````\x00`  vvHv    ````\x00`   vvv    ````\x00`          ``r`\x00`           rr`\x00`           r `\x00`          rr `\x00`          r  `\x00`        rrr  `\x00`      rrr   ``\x00`      r  ` ```\x00You feel very sleepy``` You lie do`n on the ground and try to sleep until `ornin that your destiny is not in this direction``` `esides, you're afraid you'll get lost` Y` You go `ack``\x00Uhh, \x19 think so`ethings `rong````elco`e to our ne`est dungeon cra`ler``\x00First, `hat is y is your na`e?`\x00s distri`ute your skill  skill points``\x00You have `0 points, split into attack, defense aand toughness``\x00`hat is your attttack?`\x00`hat is your deffense?`\x00`hat is your touour toughness?`\x00Don't try to checheat``\x00O`, `s``` the gahe ga`e is on``\x00"
```


I won't now state each and every substitution, they are fairly simple from now on.

```
00000000  488B8540FEFFFF    mov rax,[rbp-0x1c0]

00000007  8B80CCCC0000      mov eax,[rax+0xcccc]
```

```
    3d51: e8 cc cc ff ff  call   a22 <__abi_tag+0x6a6>

rand

    2767: e8 cc e9 ff ff  call   1138 <register_tm_clones+0x8>

scanf

    2da2: e8 cc e2 ff ff  call   1073 <strcmp@plt+0x3>

scanf

    2dce: e8 cc e2 ff ff  call   109f <mprotect@plt+0xf>

strcmp

    2dec: e8 cc e2 ff ff  call   10bd <rand@plt+0xd>

strcmp
```

\+ several more.

All this was enough to get all the necessary bytes (97-98%) to get the flag (which was encrypted using some of the binary plaintext as the key).
