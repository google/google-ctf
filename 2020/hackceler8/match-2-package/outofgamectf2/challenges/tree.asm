; Copyright 2020 Google LLC
;
; Licensed under the Apache License, Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
;
;     https://www.apache.org/licenses/LICENSE-2.0
;
; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.
BITS 64

; rdi points to:
; u64 root
; { u64 l, r } nodes[...]
; if !~l: value = r
; wanted: min, max, leaf_count

lea r15, [rdi + 8]

mov rdi, [rdi]
call fun

push rcx
push rbx
push rax

; print output
mov rax, 1
mov rdi, 1
mov rsi, rsp
mov rdx, 24
syscall

; exit
mov rax, 60
mov rdi, 0
syscall

fun:
add rdi, rdi
lea rdi, [r15 + rdi * 8]
mov r8, [rdi]
mov r9, [rdi + 8]

cmp r8, 0xffffffffffffffff
jne node

mov rax, r9
mov rbx, r9
mov rcx, 1
ret

node:

mov rdi, r8
push r9
call fun
pop rdi

push rax
push rbx
push rcx

call fun

pop r10
pop r9
pop r8

cmp r8, rax
cmovb rax, r8

cmp rbx, r9
cmovb rbx, r9

add rcx, r10

ret
