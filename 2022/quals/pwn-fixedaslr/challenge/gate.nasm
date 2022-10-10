; Copyright 2022 Google LLC
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

[bits 64]
[org 0x12345678]

xor eax, eax
mov al, 11  ; munmap
mov rdi, 0xaaaaaaaaaaaaaaaa
mov rsi, 0xbbbbbbbbbbbbbbbb
syscall

mov rax, 0xcccccccccccccccc
call rax

mov edi, eax
xor eax, eax
mov al, 60  ; exit
syscall
