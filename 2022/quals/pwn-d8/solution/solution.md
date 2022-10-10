Solution for d8
====================================
This year I made the pwn challenge "d8" in Google CTF 2022. d8 allows you to upload and run a piece of v8 code cache. The goal is crafting the code cache to achieve arbitrary code execution.

[v8 code cache](https://v8.dev/blog/code-caching) is a format to serialize the v8 heap and can be deserialized back to the v8 heap. This improves the JS loading time when the same piece of code is reused.

The format of v8 code cache is quite interesting. It doesn't directly serialize the v8 objects in the heap, but uses a bytecode to describe how to reconstruct those v8 objects. There is [a series of blog posts by PT SWARM](https://swarm.ptsecurity.com/how-we-bypassed-bytenode-and-decompiled-node-js-bytecode-in-ghidra) about how it works and it's definitely worth to read.

When studying the v8 code cache, I realized there is neither the boundary check in the deserializer, nor a validator to verify if the constructed v8 objects are legal, which gives me the idea of this pwn challenge.

V8 code cache
-------------
Here I'll briefly explain how the code cache and its bytecode work.

The serializer and deserializer of V8 code cache can be found under the [snapshot directory](https://source.chromium.org/chromium/chromium/src/+/cfec94d892c12e7237ffbb58f355af07e3c78c2e:v8/src/snapshot/). The deserializer follows the bytecode in the code cache to build v8 objects in the heap ([code](https://source.chromium.org/chromium/chromium/src/+/cfec94d892c12e7237ffbb58f355af07e3c78c2e:v8/src/snapshot/deserializer.cc;l=887)). For example, the bytecode below will create a [FixedArray object](https://source.chromium.org/chromium/chromium/src/+/299e3c8285c79b58255c33eac258d447583aa3b6:v8/src/objects/fixed-array.tq;l=6) with 3 double values:
```
0x00: 02 40 // New object with 8 slots (0x40 = 8 slots)
0x02: 4c    // Load address of FixedArray map object to slot 0
0x03: 66    // Load following 7 slots raw data
0x04: 06 00 00 00       // Slot 1: Array length in SMI: 3 (0x6>>1)
0x0c: double number 0.1 // Slot 2-3
0x14: double number 0.2 // Slot 4-5
0x1c: double number 0.3 // Slot 6-7
```
The bytecode starts with the opcode `02`, which means we want to create a heap object. It is followed by the opcodes to fill the metadata and data into the slots of the heap object.

You can notice that there are fields like array length can be given in the bytecode, but v8 deserializer doesn't check if the length field is too large for the actual length of the allocated slots. In the execution time, the v8 interpreter relies on the length field to check if the access is out of bound, so a crafted object can give us the out of bound read/write. 

Intended Solution
-----------------
### Bypassing the checksum
The first thing is to be able to run your v8 code cache. `v8::ScriptCompiler::Compile` checks if the provided JS source code matches the checksum in the provided code cache. In `runner.cc`, the JS source code is fixed to an empty string. The checksum of an empty string is 0, so you need to put 0 to the checksum field ([offset +8 in this version](https://chromium.googlesource.com/v8/v8.git/+/581a5ef7be2d340b4a0795a3b481ff7668e2252a/src/snapshot/code-serializer.h#117)) in your code cache.

### Constructing the malformed JSArray
To get the power of arbitrary read/write, we want to have a `JSArray` which has its length limit larger than its actual allocated buffer. I want to first point out a difference between the `FixedArray` and `JSArray` objects in v8. When you serialize a piece of JS code like:
```javascript
function foo() {
  return [0.1, 0.2, 0.3];
}
```
Your code cache will have two things:
1. A piece of bytecode creates the heap object `FixedArray([0.1, 0.2, 0.3])`
2. A piece of Ignition bytecode (v8's JS bytecode) defines the `function foo`, which contains a statement `CreateArrayLiteral [0], [0]`

The `FixedArray([0.1, 0.2, 0.3])` is a literal for `CreateArrayLiteral` to create the real `JSArray` object in runtime. All following reads/writes on that array will access the `JSArray` not the `FixedArray`. Therefore, if you craft a `FixedArray` in the code cache with [too large length](https://source.chromium.org/chromium/chromium/src/+/main:v8/src/objects/fixed-array.tq;l=6), it will only cause out-of-bound read when `CreateArrayLiteral` copies the data from the heap to initialize the `JSArray`, so you only have information leak. I was trapped in this pitfall for a while when writing my exploit.

In this solution, I craft the `JSArray` object manually in the code cache to define an array with too large length. So I can directly use this `JSArray` to do arbitrary read/write. The [structure of JSArray](https://source.chromium.org/chromium/chromium/src/+/121355b116ebf21e50e2abdebd1e27253fb1cce1:v8/src/objects/js-array.tq;l=52) looks like:
```
struct JSArray {
  map: Map,
  properties_or_hash: Object,
  elements: Object,
  length: Number,
}
```

The `map` can be seen as a virtual table (JS prototype) of the `JSArray`. It is a [complicated object](https://source.chromium.org/chromium/chromium/src/+/121355b116ebf21e50e2abdebd1e27253fb1cce1:v8/src/objects/map.tq;l=37) and has some fields pointing to constructor/destructor/accessor of the object. However, for the `JSArray` object, I found that as long as the bitfields in the map object are correct, there is no issue accessing the array even if other fields are missing. The v8 JS interpreter simply calls the built-in accessor functions based on the array type from the bitfields.

### Exploiting with the crafted JSArray
I craft 3 JSArray in my solution. After the code cache is deserialized, they look like below in the v8 heap:
```
0x900:  Fake map object for double array
0x950:  Fake map object for object array
0x1000: x = JSArray(map=0x900, elements=0x1010, length=0x2000, type=double array)
0x1010: FixedArray(length=0x4)
0x1100: y = JSArray(map=0x900, elements=0x1110, length=0x2000, type=double array)
0x1110: FixedArray(length=0x4)
0x1200: z = JSArray(map=0x950, elements=0x1210, length=0x2000, type=object array)
0x1210: FixedArray(length=0x10)
```

These objects are in the v8 OldSpace heap and the offsets between them are stable. The JS code in the code cache then uses them to achieve code execution:
1. Put a WASM object and an ArrayBuffer object to the `array z`.
2. Use `array x` to read the address of the WASM and the ArrayBuffer object from the `array z`.
3. Use `array x` to modify the `elements` field of `array y` and point it to the address we want to write.
4. Use `array y` to overwrite the backing store pointer of ArrayBuffer and point it to the WASM's rwx page.
5. Use the ArrayBuffer to write the shellcode and run the WASM function to trigger it.

The advantage of this flow is avoiding heap-spray and brute-forcing in the exploit and makes it very stable.

**Note that** I disable the w^x protection (wasm_write_protect_code_memory) of WASM JIT code in this challenge, which is enabled by default recently. I believe this challenge is doable with WASM w^x protection, but I didn't have enough time to test it and I don't think it's the main point of this challenge, so I decided to disable it :-)
