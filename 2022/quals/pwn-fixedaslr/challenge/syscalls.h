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
#pragma once
#include <stdint.h>
#ifndef size_t
#  define size_t uint64_t
#endif

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

extern size_t sys_write(int fd, const void *buf, size_t count);
extern size_t sys_read(int fd, void *buf, size_t count);
extern void sys_exit(int code) __attribute__ ((noreturn));
extern void sys_getrandom(void *buf, size_t buflen, unsigned int flags);
