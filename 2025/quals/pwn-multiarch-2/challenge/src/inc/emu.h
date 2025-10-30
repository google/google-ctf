/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>
#include <sys/mman.h>

#include "loader.h"
#include "log.h"

// index into emulator_t.gp_regs
#define REG_A 0
#define REG_B 1
#define REG_C 2
#define REG_D 3

#define EVA_CODE_BASE 0x1000
#define EVA_DATA_BASE 0x2000
#define EVA_STACK_BASE 0x8000

#define PAGE_SIZE 0x1000

#define ARCH_STACKVM 0
#define ARCH_REGVM 1

// bit offset on the flags byte
#define FLAG_Z 0
#define FLAG_O 1
#define FLAG_S 2

#define PL_USER 0
#define PL_SYS 1

#define SYS_READ_DWORD 0
#define SYS_READ_BYTES 1
#define SYS_WRITE 2
#define SYS_PRNG_SEED 3
#define SYS_PRNG_GET 4
#define SYS_FLAG 5
#define SYS_MMAP 6

// emulator virtual address
typedef uint32_t eva_t;

typedef struct __attribute__((packed)) {
    void* ptr;
    eva_t eva;
} dynchunk_t;

#define MAX_DYNCHUNKS 5
#define DYNCHUNK_SZ 0x200

typedef struct __attribute__((packed)) {
    uint8_t* code_page;
    uint8_t* data_page;
    uint8_t* stack_page;

    uint8_t* arch_bitmap;
    size_t arch_bitmap_sz;

    char* (*flag)(void);

    bool faulted;
    uint8_t cpl;
    uint8_t flags;

    eva_t pc;
    eva_t sp;
    uint32_t gp_regs[4];   // this needs to be directly preceeding pages for the oob mapping bug

    dynchunk_t chunks[MAX_DYNCHUNKS];
    uint8_t chunk_count;
} emulator_t;

emulator_t* new_emulator(program_t* prog);
void free_emulator(emulator_t* emu);

// returns false if execution is done (ie, a HLT was executed or a fault was triggered)
bool execute_next_instruction(emulator_t* emu);

void dump_emulator_state(emulator_t* emu, bool include_stack);