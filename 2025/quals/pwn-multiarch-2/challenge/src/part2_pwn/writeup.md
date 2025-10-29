# patch for dumping each insn effect

before:
```
004029d1    uint64_t sub_4029d1(void* arg1)

004029d1  53                 push    rbx {__saved_rbx}
004029d2  4889fb             mov     rbx, rdi
004029d5  e800eeffff         call    sub_4017da
004029da  0fb6c0             movzx   eax, al
004029dd  85c0               test    eax, eax
004029df  7429               je      0x402a0a

004029e1  83f801             cmp     eax, 0x1
004029e4  742e               je      0x402a14

004029e6  488b0d13370000     mov     rcx, qword [rel stderr]
004029ed  ba0f000000         mov     edx, 0xf
004029f2  be01000000         mov     esi, 0x1
004029f7  488d3dfe160000     lea     rdi, [rel data_4040fc]  {"[E] nice qubit\n"}
004029fe  e89de7ffff         call    fwrite
00402a03  b800000000         mov     eax, 0x0

00402a08  5b                 pop     rbx {__saved_rbx}
00402a09  c3                 retn     {__return_addr}

00402a0a  4889df             mov     rdi, rbx
00402a0d  e844f0ffff         call    sub_401a56
00402a12  ebf4               jmp     0x402a08

00402a14  4889df             mov     rdi, rbx
00402a17  e836f6ffff         call    sub_402052
00402a1c  ebea               jmp     0x402a08
```

patch (nop out the rest of the func starting at 0x4029d5):
```
mov rsi, 1
call 0x402a1e  ; dump the state

mov rdi, rbx
call 0x4017da  ; get the arch bit

; call the right insn handler
movzx eax, al
test eax, eax
je zero
cmp eax, 0x1
je notzero

mov eax, 0x0
done:
pop rbx
retn

zero:
mov rdi, rbx
call 0x401a56
jmp done

notzero:
mov rdi, rbx
call 0x402052
jmp done
```

end result:
```
004029d1    int64_t sub_4029d1(void* arg1)

004029d1  53                 push    rbx {__saved_rbx}
004029d2  4889fb             mov     rbx, rdi
004029d5  48c7c601000000     mov     rsi, 0x1
004029dc  e83d000000         call    sub_402a1e
004029e1  4889df             mov     rdi, rbx
004029e4  e8f1edffff         call    sub_4017da
004029e9  0fb6c0             movzx   eax, al
004029ec  85c0               test    eax, eax
004029ee  740c               je      0x4029fc

004029f0  83f801             cmp     eax, 0x1
004029f3  7411               je      0x402a06

004029f5  b800000000         mov     eax, 0x0

004029fa  5b                 pop     rbx {__saved_rbx}
004029fb  c3                 retn     {__return_addr}

004029fc  4889df             mov     rdi, rbx
004029ff  e852f0ffff         call    sub_401a56
00402a04  ebf4               jmp     0x4029fa

00402a06  4889df             mov     rdi, rbx
00402a09  e844f6ffff         call    sub_402052
00402a0e  ebea               jmp     0x4029fa
```