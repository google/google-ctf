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
#define HELPER_FUNC(REG) \
__asm("                                  \n\
  .globl _debug_set_reg_" REG "          \n\
  .type _debug_set_reg_" REG ", @function\n\
  _debug_set_reg_" REG ":               \n\
    push %rdi                            \n\
    pop %" REG "                         \n\
    ret                                  \n\
")

HELPER_FUNC("rdi");
HELPER_FUNC("rsi");
HELPER_FUNC("rax");
HELPER_FUNC("rbx");
HELPER_FUNC("rcx");
HELPER_FUNC("rdx");
HELPER_FUNC("rsp");
HELPER_FUNC("rbp");
HELPER_FUNC("r8");
HELPER_FUNC("r9");
HELPER_FUNC("r10");
HELPER_FUNC("r11");
HELPER_FUNC("r12");
HELPER_FUNC("r13");
HELPER_FUNC("r14");
HELPER_FUNC("r15");
