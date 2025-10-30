# Syntax

- instructions are prefixed with the vm
- insns, regs, and imms are case insensitive
- imms are prefixed with `#`
- absolute addrs are prefixed with `@`
- labels get translated to absolute addrs
- code section starts with `.code` label, data with `.data`
- comments are prefixed with `//`

```
.code
// stack instruction - push 0x10 onto the stack
S.LDB #0x10
S.lDb #0x10
s.ldb #16

// register instruction - move 42 into A
R.MOV A, #0x2A
R.MOV A, #0x2a
r.MoV A, #42

some_thing:
R.HLT

R.JMP some_thing
R.JMP @0x1234
R.JMP @5678

// push the addr of the data at label `prompt` to the stack
S.LDP prompt

.data
prompt: "Welcome to multiarch!"
encdata: "\xaa\xbb\xcc\xdd"
```

# `[S]` - Stack VM (arch bit == 0)

## Data movement

`10 <byte> 00 00 00` - LDB <byte>
`20 <word> 00 00` - LDW <word>
`30 <dword>` - LDD <dword>
`40 <dword>` - LDP <addr>
    push the value at addr
`50 00 00 00 00` - POP

## ALU

`60 00 00 00 00` - ADD
`61 00 00 00 00` - SUB
`62 00 00 00 00` - XOR
`63 00 00 00 00` - AND

## Control flow

`70 <dword>` - JMP <addr>
`71 <dword>` - JEQ <addr>
`72 <dword>` - JNE <addr>
`80 00 00 00 00` - CMP

## Misc

`a0 00 00 00 00` - SYS
`ff ff ff ff ff` - HLT

# `[R]` - Register VM (arch bit == 1)

## Data movement

`mov` instruction: `11xx xyyy` (>= 0xc0) - 1 byte base size
- `x`: 0-3 is dst reg A-D. 4 is addr. can't write to imm
- `y`: 0-3 is src reg A-D. 4 is addr, 5 is imm
- if `x` is 4 or 5, next 4 bytes are the dst addr or imm
- if `y` is 4 or 5, following 4 bytes are the src addr or imm
    can `mov $gp, sp` as well, y==6 here

mov types:
- mov gpr, gpr
- mov gpr, imm
- mov gpr, sp
- mov *gpr, gpr
- mov *gpr, imm
- mov gpr, *gpr

could do a prefix byte - `1010 xxyy` (`0xA_`)
    xx is the dst arg flags, yy is the src
    00 -> handle normally
    01 -> deref (if set and arg is not a gpr, will fault)


`10 <dword>` - PUSH <dword>
`1(1-4)` - PUSH <reg>
`1(5-8)` - POP <reg>

## ALU

`20 xy` - ADD [r32, r32] (x is dst, y is src; 1-4)
`21 x0 <dword>` - ADD [r32, imm32]
`30 xy` - SUB [r32, r32] (x is dst, y is src; 1-4)
    x==5 -> sp
`31 x0 <dword>` - SUB [r32, imm32]
`40 xy` - XOR [r32, r32] (x is dst, y is src; 1-4)
`41 x0 <dword>` - XOR [r32, imm32]
`50 xy` - MUL [r32, r32] (x is dst, y is src; 1-4)
`51 x0 <dword>` - MUL [r32, imm32]

## Control flow

`60 <dword>` - CALL <addr>
`61 <byte>` - RET <dword count to reset stack by>
`62 <dword>` - JEQ <addr>
`63 <dword>` - JNE <addr>
`64 <dword>` - JG <addr>
`68 <dword>` - JMP <addr>

`7x` - CMP reg, reg
    low 2 bits src
    high 2 bits dst

`8x <dword>` - CMP reg, imm
    low 2 bits are the reg

## Misc

`00` - HLT
`01` - SYS

# jmp flags

jeq == FLAG_Z
jne == !FLAG_Z