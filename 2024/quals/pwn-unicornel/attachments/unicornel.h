// Copyright 2024 Google LLC
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

#include "unicorn/unicorn.h"
#include <stdbool.h>
#include <stdatomic.h>
#define MAX_PROCESSES 8

struct unicornelf {
    uc_arch arch;
    uc_mode mode;
    struct {
        unsigned long va;
        unsigned long length;
    } maps[4];
    unsigned short code_length;
    unsigned char num_maps;
};
struct buffer_ref {
    unsigned long va;
    unsigned long length;
    unsigned handle;
    bool unmap_on_rewind;
};
struct process {
    pthread_t thread;
    uc_arch arch;
    int outfd;
    uc_engine *uc;
    unsigned long entrypoint;
    uc_context* bookmark;
    struct buffer_ref sbr;
    struct {
        unsigned long va;
        unsigned long length;
    } maps[4];
    unsigned short code_length;
    unsigned char pid;
    unsigned char num_maps;
    bool transition;
    bool paused;
};
struct shared_buffer {
    volatile atomic_uint refs;
    void* buffer;
    unsigned length;
};
static unsigned int call_regs[UC_ARCH_MAX][4] = {
    {0,0,0,0}, //NONE
    {UC_ARM_REG_R0,UC_ARM_REG_R1,UC_ARM_REG_R2,UC_ARM_REG_R3}, //UC_ARCH_ARM
    {UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3}, //UC_ARCH_ARM64
    {UC_MIPS_REG_A0,UC_MIPS_REG_A1,UC_MIPS_REG_A2,UC_MIPS_REG_A3}, //UC_ARCH_MIPS
    {UC_X86_REG_RAX,UC_X86_REG_RBX,UC_X86_REG_RCX,UC_X86_REG_RDX}, //UC_ARCH_X86
    {UC_PPC_REG_0,UC_PPC_REG_1,UC_PPC_REG_2,UC_PPC_REG_3}, //UC_ARCH_PPC
    {UC_SPARC_REG_O0,UC_SPARC_REG_O1,UC_SPARC_REG_O2,UC_SPARC_REG_O3}, //UC_ARCH_SPARC
    {UC_M68K_REG_D0,UC_M68K_REG_D1,UC_M68K_REG_D2,UC_M68K_REG_D3}, //UC_ARCH_M68K
    {UC_RISCV_REG_A0,UC_RISCV_REG_A1,UC_RISCV_REG_A2,UC_RISCV_REG_A3}, //UC_ARCH_RISCV
    {UC_S390X_REG_R0,UC_S390X_REG_R1,UC_S390X_REG_R2,UC_S390X_REG_R3}, //UC_ARCH_S390X
    {UC_TRICORE_REG_D0,UC_TRICORE_REG_D1,UC_TRICORE_REG_D2,UC_TRICORE_REG_D3}, //UC_ARCH_TRICORE
};
static unsigned int ip_reg[UC_ARCH_MAX] = {
    0,
    UC_ARM_REG_PC,
    UC_ARM64_REG_PC,
    UC_MIPS_REG_PC,
    UC_X86_REG_RIP,
    UC_PPC_REG_PC,
    UC_SPARC_REG_PC,
    UC_M68K_REG_PC,
    UC_RISCV_REG_PC,
    UC_S390X_REG_PC,
    UC_TRICORE_REG_PC
};
extern long (*syscalls[])(struct process* current);
extern struct shared_buffer shared_buffers[MAX_PROCESSES];
extern bool arch_used[UC_ARCH_MAX];
extern pthread_mutex_t task_lock;
extern struct process* processes[MAX_PROCESSES];

unsigned long ARG_REGR(struct process* current,unsigned reg);
void ARG_REGW(struct process* current,unsigned reg, unsigned long value);
void hook_call(uc_engine* uc, unsigned intno, void* user_data);
