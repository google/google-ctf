/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "internal.h"


/*
 * WRPKRU with sanity checking appended to ensure that the instruction can only
 * be used in 64-bit mode and can only be used to write one specific key.
 * Clobbers: rax, rcx, rdx
 */
.macro wrpkru_safe KEY_STATE, WRPKRU_LABEL
#ifdef INSECURE
jmp 2f
#endif
xor %ecx, %ecx
xor %edx, %edx
mov \KEY_STATE, %eax
.global \WRPKRU_LABEL
\WRPKRU_LABEL:
wrpkru
/*
 * Check CS against a fixed value to make sure we're in 64-bit mode.
 * Linux always uses the same CS for 64-bit userspace code unless we're running
 * under Xen PV (in which case this would be a different fixed value).
 * This code must have the same meaning in 32bit mode.
 */
mov %cs, %cx
cmp $0x33, %cx
je 1f
ud2
1:
/* Ensure that an attacker did not jump directly to WRPKRU. */
cmp %eax, \KEY_STATE
je 2f
ud2
2:
.endm


/*
 * rdi: arguments to be passed through to privileged call handler
 */
.globl gatekey_call
gatekey_call:
wrpkru_safe gatekey_trusted_key_state(%rip), safe_wrpkru_trusted
cld /* Reset hazardous processor state. */

/* Pivot over to the trusted stack and push the address of the main stack. */
movq %rsp, %rcx
leaq key_gate_stack + KEY_GATE_STACK_SIZE(%rip), %rsp
pushq %rcx

/* Invoke the C handler. */
call gatekey_call_handler
mov %rax, %rdi

/* Pivot the stack back. */
popq %rsp

jmp gatekey_exit_trusted
.size gatekey_call, .-gatekey_call



/*
 * rdi: value to return
 */
.globl gatekey_exit_trusted
gatekey_exit_trusted:
wrpkru_safe gatekey_normal_key_state(%rip), safe_wrpkru_normal
mov %rdi, %rax
ret
.size gatekey_exit_trusted, .-gatekey_exit_trusted



/*
 * Invoke syscall.
 * gatekey_syscall(arg1, arg2, arg3, arg4, arg5, nr)
 *       call abi:  rdi   rsi   rdx   rcx    r8  r9
 *    syscall abi:  rdi   rsi   rdx   r10    r8  rax
  */
.globl gatekey_syscall
gatekey_syscall:
mov %r9, %rax
mov %rcx, %r10
syscall
ret
.size gatekey_syscall, .-gatekey_syscall
