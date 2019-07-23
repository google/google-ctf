; Copyright 2019 Google LLC
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

%define __NR_mmap   9
%define __NR_munmap 11

%define MAP_PRIVATE   0x02
%define MAP_ANONYMOUS 0x20

%define PROT_READ     0x01
%define PROT_WRITE    0x02

mov r14, rdi

new_stack:
  ; We need to have a new stack since the old one will be munmapped.
  xor r9, r9                           ; off
  xor r8, r8                           ; fd
  mov r10, MAP_PRIVATE | MAP_ANONYMOUS ; flags
  mov rdx, PROT_READ | PROT_WRITE      ; permissions
  mov rsi, 0x1000                      ; size
  xor rdi, rdi                         ; addr
  mov rax, __NR_mmap
  syscall
  lea rsp, [rax + 0x1000]


  mov rax, r14
unmap_all:
  ; Unmap everything except newly created pages (won't be in the list).
  mov rdi, [rax]
  mov rsi, [rax + 8]
  cmp rsi, 0
  jz done
  push rax
  mov rax, __NR_munmap
  syscall
  pop rax
  mov qword [rax], 0
  mov qword [rax + 8], 0
  add rax, 16
  jmp unmap_all


done:
  xor rax, rax
  xor rbx, rbx
  xor rcx, rcx
  xor rdx, rdx
  xor rsi, rsi
  xor rdi, rdi
  xor r8, r8
  xor r9, r9
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15

  xor rbp, rbp
  ; User provided code will be loaded here.
