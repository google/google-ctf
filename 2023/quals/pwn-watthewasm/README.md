# WatTheWasm

This is a v8 exploitation challenge. You can upload a wasm module and need to exploit a bug introduced in the attached patch to gain RIP control.

The challenge reads a single line input, base64 decodes it, writes it to a file and then loads that as a wasm module in v8 and runs `pwn`.

## The bug

The bug is in the liftoff compiler. It changes the cache state under a conditional branch, this makes the compiler believe some register was spilled to the stack and the instance pointer was cached.
You can turn the first into an info leak and the second into arbitrary memory corruption and code exec.

For simplicity, there's a print\_flag embedddd in the binary, so one shot RIP control is enough to solve it.

You can find an exploit in healthcheck/pwn.wat.
