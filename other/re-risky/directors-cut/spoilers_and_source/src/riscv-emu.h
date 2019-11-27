#pragma once
// Copyright 2018 Google LLC
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
//
// RISC-V 64-bit ultra-small emu (made for a CTF).
// Author: Gynvael Coldwind (Google Inc.)

#include <stdbool.h>
#include <stdint.h>

#define RISCV_MAX_MEM_REGIONS 4


typedef struct rv_mem_region_st {
  uint8_t *mem;
  size_t start;
  size_t size;
  bool writable;
} rv_mem_region_t;

typedef struct rv_ctx_st {
  uint64_t pc;
  union {
    uint64_t x[32];
    struct {
      uint64_t zero;  // x0, special case, always zero.
      uint64_t ra;  // x1
      uint64_t sp;  // x2
      uint64_t gp;  // x3
      uint64_t tp;  // x4
      uint64_t t0;  // x5
      uint64_t t1;  // x6
      uint64_t t2;  // x7 (of course t3 has to be at x28...)
      union {
        uint64_t s[2];  // x8-x9
        uint64_t fp;  // x8
      };
      uint64_t a[12];  // x10-x27
      uint64_t t3;  // x28
      uint64_t t4;  // x29
      uint64_t t5;  // x30
      uint64_t t6;  // x31
    };
  };
  uint64_t *t[7];  // Initialized with pointers to t0-t6.

  rv_mem_region_t regions[RISCV_MAX_MEM_REGIONS];
  size_t regions_used;
} rv_ctx_t;

void rv_init(rv_ctx_t *ctx);

void rv_mem_add(
    rv_ctx_t *ctx, void *mem, size_t start, size_t size, bool writable);
rv_mem_region_t* rv_mem_translate(rv_ctx_t *ctx, size_t addr);

bool rv_mem_write(rv_ctx_t *ctx, size_t addr, const void *src, size_t size);
bool rv_mem_read(rv_ctx_t *ctx, size_t addr, void *dst, size_t size);

bool rv_execute_instruction(rv_ctx_t *ctx);
void rv_run(rv_ctx_t *ctx, size_t start_pc);



