// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Author: Ian Eldred Pudney

#ifndef EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_SYSCALL_H_
#define EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_SYSCALL_H_

#include <unistd.h>
#include <sys/syscall.h>
#include <asm/unistd.h>
#include <sys/types.h>

#define SYSCALL3(ret, number, arg1, arg2, arg3) \
asm volatile  \
(  \
    "syscall"  \
    : "=a" (ret)  \
    : "0"(number), "D"(arg1), "S"(arg2), "d"(arg3)  \
    : "rcx", "r11", "memory"  \
);

#endif  // EXPERIMENTAL_USERS_IPUDNEY_POLYMORPH_SYSCALL_H_
