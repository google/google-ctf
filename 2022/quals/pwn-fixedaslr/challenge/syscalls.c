// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <stdint.h>
#define size_t uint64_t
#define NULL ((void*)0)

extern uint64_t syscall0(int syscall);
extern uint64_t syscall1(
    int syscall, uint64_t rdi
);
extern uint64_t syscall2(
    int syscall, uint64_t rdi, uint64_t rsi
);
extern uint64_t syscall3(
    int syscall, uint64_t rdi, uint64_t rsi, uint64_t rdx
);
extern uint64_t syscall4(
    int syscall, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10
);
extern uint64_t syscall5(
    int syscall, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10,
    uint64_t r8
);
extern uint64_t syscall6(
    int syscall, uint64_t rdi, uint64_t rsi, uint64_t rdx, uint64_t r10,
    uint64_t r8, uint64_t r9
);

__asm("                                \n\
  .globl syscall0                      \n\
  .type syscall0, @function            \n\
  syscall0:                            \n\
    mov %eax, %edi                     \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
  .globl syscall1                      \n\
  .type syscall1, @function            \n\
  syscall1:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
.globl syscall2                        \n\
  .type syscall2, @function            \n\
  syscall2:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
.globl syscall3                        \n\
  .type syscall3, @function            \n\
  syscall3:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    mov %rdx, %rcx                     \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
.globl syscall4                        \n\
  .type syscall4, @function            \n\
  syscall4:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    mov %rdx, %rcx                     \n\
    mov %r10, %r8                      \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
.globl syscall5                        \n\
  .type syscall5, @function            \n\
  syscall5:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    mov %rdx, %rcx                     \n\
    mov %r10, %r8                      \n\
    mov %r8,  %r9                      \n\
    syscall                            \n\
    ret                                \n\
                                       \n\
  .globl syscall6                      \n\
  .type syscall6, @function            \n\
  syscall6:                            \n\
    mov %eax, %edi                     \n\
    mov %rdi, %rsi                     \n\
    mov %rsi, %rdx                     \n\
    mov %rdx, %rcx                     \n\
    mov %r10, %r8                      \n\
    mov %r8,  %r9                      \n\
    mov %r9, qword ptr [%rsp+8]        \n\
    syscall                            \n\
    ret                                \n\
");

size_t sys_write(int fd, const void *buf, size_t count) {
  return syscall3(1, (uint64_t)fd, (uint64_t)buf, count);
}

size_t sys_read(int fd, void *buf, size_t count) {
  return syscall3(0, (uint64_t)fd, (uint64_t)buf, count);
}

void sys_exit(int code) {
  syscall1(60, code);
}

void *sys_mmap(
    uint64_t addr, uint64_t len, uint64_t prot, uint64_t flags,
    uint64_t fd, uint64_t off) {
  return (void*)syscall6(9, addr, len, prot, flags, fd, off);
}

void sys_mprotect(uint64_t addr, uint64_t len, uint64_t prot) {
  syscall3(10, addr, len, prot);
}

void sys_munmap(uint64_t addr, uint64_t len) {
  syscall2(11, addr, len);
}

int sys_open(const char *fname, int flags, int mode) {
  return (int)syscall3(2, (uint64_t)fname, flags, mode);
}

void sys_close(int fd) {
  syscall1(3, (uint64_t)fd);
}

void sys_lseek(int fd, size_t offset, unsigned int origin) {
  syscall3(8, (uint64_t)fd, offset, origin);
}

void sys_getrandom(void *buf, size_t buflen, unsigned int flags) {
  syscall3(318, (uint64_t)buf, buflen, flags);
}
