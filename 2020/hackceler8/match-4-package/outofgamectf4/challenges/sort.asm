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
; rdi points to:
; u64 count
; u64 elements[count]

push rdi

lea r14, [rdi + 8]
mov rax, [rdi]
lea r15, [rdi + rax * 8]

outer:

mov rax, r14
mov rdx, 0

inner:

mov rbx, [rax]
add rax, 8
mov rcx, [rax]

; swap if unsorted
cmp rbx, rcx
jbe no_swap

mov [rax], rbx
sub rax, 8
mov [rax], rcx
add rax, 8

mov rdx, 1

no_swap:

cmp rax, r15
jne inner

cmp rdx, 1
je outer

; print output
mov rax, 1
mov rdi, 1
mov rsi, r14
mov rdx, r15
sub rdx, r14
add rdx, 8
syscall

; exit
mov rax, 60
mov rdi, 0
syscall

