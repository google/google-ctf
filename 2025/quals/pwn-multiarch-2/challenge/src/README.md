# multiarch

Part 1 (rev):

> Stacks are fun, registers are easy, but why do one when you can do both? Welcome to the multiarch.

Part 2 (pwn):

> My program was cool, but I bet you can write even cooler ones! Send them to my server, and try to get the flag from `/flag`.

## Design

### Emulator
32-bit width

4 gp regs
flags (ZF)
pc
stack pointer

privilege level - always 1

virtual address space:
- `0x1000 - 0x2000` - r|x, code
- `0x2000 - 0x3000` - r, data
- `0x8000 - 0x9000` - r|w, stack

maybe can map in more memory?

System calls:
- read from stdin
- write to stdout
- prng seed
- prng get byte
- print flag env var

could have a `fault` concept that would let players dump the state of the vm to make debugging easier?
- try to write to mem you dont have privs for
- execute an invalid opcode
- privileged syscall with insufficient privilege

### Arch 1 - Custom Stack-based VM
fixed width RISC instruction set
5 byte instruction width

```
LDB [imm8]  - load byte, sp+1
LDW [imm16] - load word, sp+2
LDD [imm32] - load dword, sp+4
LDP [m32]   - load dword at pointer, sp+4
POP - move the stack pointer back 4 bytes

ADD - add the top 2 things on the stack, push the result
SUB - subtract ^^
XOR - xor ^^

JMP [addr] - branch to the addr
CALL [addr] - save the return addr to the stack
    this needs some thinking, how does the
    maybe just need a base pointer concept to have sliding stack frames

CMP - check the top 2 things on the stack, set flags
JEQ - jmp if they are equal

SYS - top stack element is the number, and then args if needed
HLT     - end program
```

### Arch 2 - Custom Register-based VM
variable width CISC instruction set

need instruction encoding bits representing the width and types of the parameters
(dst, src)
```
# dst can only be a gp register
MOV [r32, r32]
MOV [r32, imm32]
MOV [m32, r32]   - write contents of reg to mem addr
MOV [m32, imm32] - write imm to mem addr
# can do any mix of r/m/imm in src or dst

PUSH [r32]
PUSH [imm32]
POP [r32]

ADD [r32, r32]
ADD [r32, imm8]
ADD [r32, imm16]
ADD [r32, imm32]
SUB ...
XOR ...
MUL ... - result is stored in A:B

CALL [addr] - push the next insn addr to the stack and then jmp to the addr
RET [sz]    - reclaim $sz stack dwords before popping into $pc

CMP [r32, r32]
CMP [r32, imm]

JE - zf==1
JG - of==1

SYS - number in A, args in B,C,D
HLT     - end program
```

### Payload Format

header defining the segments of the file
- code segment
- data segment
- arch segment
  - 1 bit==1 insn

- header `MASM`
- seg chunk
  - type
  - offset
  - sz

## Potential bugs

- call/ret stuff, if you mix up stack and reg based, could maybe confuse the return? idk how exploitable that is

- can do some safety stuff that is skipped by doing a mix of stack `ldb` insns and then a reg `call` or something
  - this is no different then push'ing + ret'ing

```
[S] ldb 1
[S] ldb 2
[S] ldb 3
[S] ldb 4
[S] pop  - actually dont need this i dont think
[R] ret
```
this would indirectly jump to 0x04030201 or something

can make it so that the [R] mov instructions only work on gp registers

- privileged instructions that expose more dangerous functionality, and missing checks on the gating of those?
  - could be something like the reg syscall handler properly validates, but the stack syscall handler uses the reg validator (ie, checks if A is a privileged syscall but the actual syscall number is on the stack)
  - include a function that doesn't get used anywhere to mutate the privilege level, have a debug log string of something like `TODO: implement privilege level switching` or something.
  - could use this to introduce a mmap syscall

- make a bug in the address translation for mmap'd pages that lets them oob. int overflow?
  - could misalign the stack through the `ldb` instruction to cause things to get read off the stack wrong maybe

- misalign the stack to do a 3 byte overflow off the end of the mapped region
  - feel like rust will block this


alloc some mem
corrupt the stack to get it onto the edge of the new mem boundary

misalign the stack and then do a reg relative read or something that lets you overflow off the edge into some other memory
leverage this into oob r/w
or we can do this in a way that corrupts the memory mappings into the emulator
    harcode in the bounds/mapping for code/data/stack, so that you have to use the dynamic memory allocation to hit the vulnerable code path
    this would let you construct an arb r/w primitive

    do we need a leak?
    could maybe use malloc for the mem, then somehow get a libc addr into the mem and then oob read from the allocated chunk to get a leak
        dont want this to just become heap pwn though

## Part 1

Payload design:
- part 1 - only regvm
  - read dword, xor it against a key, check if its right
- part 2 - only stackvm
  - naive hash a string input
- part 3 - both
  - idk
- part 4 - both
  - use the prng. seed=0xac0ffee

mix of cleartext strings and encrypted strings/data

probably have a remote for this one as well. flag in env var, have a syscall to print the flag env var contents. dont set that var in part 2, that way the emulator binary hash is the same and there isnt an easy cheese on 2

## Part 2

if we do a python server that reads in a program from the user, writes to disk, and then executes, they'll need to write shellcode or something to read the flag in and write it to stdout

runner needs to capture stdout. or maybe we can just redirect stdin/stdout in a way that lets execve(/bin/sh) work correctly


how to introduce a leak?
- maybe use malloc/free in some of the setup stuff, and then overlap a chunk size and dont zero it all out so there is a stray pointer accessible to read from