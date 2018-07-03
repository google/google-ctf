; Copyright 2018 Google LLC
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

	BITS	64

	;; This code is executed from a 64-bit context, straight from an
	;; untrusted 32-bit context.

	;; In protected mode, popping a segment selector into a segment register
	;; automatically causes the descriptor information associated with that
	;; segment selector to be loaded into the hidden (shadow) part of the
	;; segment register [...]
	;; A NULL value (0000-0003) may be popped into the DS, ES, FS, or GS
	;; register without causing a general protection fault. However, any
	;; subsequent attempt to reference a segment whose corresponding
	;; segment register is loaded with a NULL value causes a general
	;; protection exception (#GP). In this situation, no memory reference
	;; occurs and the saved value of the segment register is NULL.

	;; Note that FS and GS base can also be updated directly, but wrfsbase
	;; and wrgsbase are forbidden because CR4.[G|F]SGSBASE = 0. They are
	;; initialized by the glibc using arch_prctl(ARCH_SET_FS).

	;; I am not sure wether an exploitable vector exists, but since the
	;; glibc makes use of FS and GS, just be safe and ensure that FS and GS
	;; are NULL.
	mov	rax, fs
	test	rax, rax
	jnz	bad
	mov	rax, gs
	test	rax, rax
	jnz	bad

	;; save rsp into rbx
	mov	rbx, rsp

	;; setup stack
	mov	rsp, 0xdeadbeefdeaddead
	push	rbx

	;; call kernel function
	mov	rax, 0xdeadbeefdeadc0de
	call	rax

	;; restore rsp back to rbx
	pop	rbx
	mov	rsp, rbx

	;; trampoline to 32-bit code (segment selector 0xf)
	;; 0xfffffff5: ret gadget
	mov	rcx, 0xffffffff5
	push	rcx
	retf

bad:
	ud2
