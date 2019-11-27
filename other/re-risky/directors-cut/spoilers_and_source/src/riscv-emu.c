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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "riscv-emu.h"

typedef struct rv_opcode_info_st {
  uint32_t opcode;
  uint32_t rd;
  uint32_t funct;
  uint32_t rs1;
  uint32_t rs2;
  uint32_t imm;
} rv_opcode_info_t;

#define SIGNEXT(value, top_bit) \
    (((0ULL - (((value) >> (top_bit)) & 1)) << ((top_bit) + 1)) | (value))
#define MASK(bits) ((1ULL << (bits)) - 1)
#define BITFIELD(src, lower_bit, upper_bit) ((src >> lower_bit) & MASK(upper_bit - lower_bit + 1))

#ifndef TEST
// Simple memcpy implementation for the standalone version.
void *memcpy(void *dest, const void *src, size_t n) {
  uint8_t *d = (uint8_t*)dest;
  uint8_t *s = (uint8_t*)src;
  for (size_t i = 0; i < n; i++) {
    *d++ = *s++;
  }
  return dest;
}
#endif

// Decodes opcode (7 bits) and funct3 as in 32-bit instruction format.
static void rv_decode_opportunistic(rv_opcode_info_t *info, uint32_t opcode) {
  info->opcode = BITFIELD(opcode, 0, 6);
  info->funct = BITFIELD(opcode, 12, 14);
}

static void rv_decode_R(rv_opcode_info_t *info, uint32_t opcode) {
  info->opcode = BITFIELD(opcode, 0, 6);
  info->rd = BITFIELD(opcode, 7, 11);
  info->funct = BITFIELD(opcode, 12, 14) | (BITFIELD(opcode, 25, 31) << 3);
  info->rs1 = BITFIELD(opcode, 15, 19);
  info->rs2 = BITFIELD(opcode, 20, 24);
}

static void rv_decode_I(rv_opcode_info_t *info, uint32_t opcode) {
  info->opcode = BITFIELD(opcode, 0, 6);
  info->rd = BITFIELD(opcode, 7, 11);
  info->funct = BITFIELD(opcode, 12, 14);
  info->rs1 = BITFIELD(opcode, 15, 19);
  info->imm = BITFIELD(opcode, 20, 31);
  info->imm = SIGNEXT(info->imm, 11);
}

static void rv_decode_S(rv_opcode_info_t *info, uint32_t opcode) {
  info->opcode = BITFIELD(opcode, 0, 6);
  info->funct = BITFIELD(opcode, 12, 14);
  info->rs1 = BITFIELD(opcode, 15, 19);
  info->rs2 = BITFIELD(opcode, 20, 24);
  info->imm = BITFIELD(opcode, 7, 11) | (BITFIELD(opcode, 25, 31) << 5);
  info->imm = SIGNEXT(info->imm, 11);
}

static void rv_decode_B(rv_opcode_info_t *info, uint32_t opcode) {
  info->opcode = BITFIELD(opcode, 0, 6);
  info->funct = BITFIELD(opcode, 12, 14);
  info->rs1 = BITFIELD(opcode, 15, 19);
  info->rs2 = BITFIELD(opcode, 20, 24);
  info->imm = (BITFIELD(opcode, 7, 7) << 11) |
              (BITFIELD(opcode, 8, 11) << 1) |
              (BITFIELD(opcode, 25, 30) << 5) |
              (BITFIELD(opcode, 31, 31) << 12);
  info->imm = SIGNEXT(info->imm, 12);
}

static void rv_decode_U(rv_opcode_info_t *info, uint32_t opcode) {
  info->opcode = BITFIELD(opcode, 0, 6);
  info->rd = BITFIELD(opcode, 7, 11);
  info->imm = BITFIELD(opcode, 12, 31) << 12;
  // Doesn't need SIGNEXT.
}

static void rv_decode_UJ(rv_opcode_info_t *info, uint32_t opcode) {
  info->opcode = BITFIELD(opcode, 0, 6);
  info->rd = BITFIELD(opcode, 7, 11);
  info->imm = (BITFIELD(opcode, 12, 19) << 12) |
              (BITFIELD(opcode, 20, 20) << 11) |
              (BITFIELD(opcode, 21, 30) << 1) |
              (BITFIELD(opcode, 31, 31) << 20);
  info->imm = SIGNEXT(info->imm, 20);
}

void rv_init(rv_ctx_t *ctx) {
  memset(ctx, 0, sizeof(*ctx));

  // Please look the other way.
  ctx->t[0] = &ctx->t0;
  ctx->t[1] = &ctx->t1;
  ctx->t[2] = &ctx->t2;
  ctx->t[3] = &ctx->t3;
  ctx->t[4] = &ctx->t4;
  ctx->t[5] = &ctx->t5;
  ctx->t[6] = &ctx->t6;
}

void rv_mem_add(
    rv_ctx_t *ctx, void *mem, size_t start, size_t size, bool writable) {
  // Note: Missing boundary check. Missing overlap check.
  rv_mem_region_t *region = &ctx->regions[ctx->regions_used++];
  region->mem = (uint8_t*)mem;
  region->start = start;
  region->size = size;
  region->writable = writable;
}

rv_mem_region_t* rv_mem_translate(rv_ctx_t *ctx, size_t addr) {
  for (size_t i = 0; i < ctx->regions_used; i++) {
    if (addr >= ctx->regions[i].start &&
        addr < ctx->regions[i].start + ctx->regions[i].size) {
      return &ctx->regions[i];
    }
  }
  return NULL;
}

bool rv_mem_write(rv_ctx_t *ctx, size_t addr, const void *src, size_t size) {
  // Note: Missing support for cross-region writes. Missing signal support.
  rv_mem_region_t *region = rv_mem_translate(ctx, addr);
  if (region == NULL) {
#ifdef TEST_VERBOSE
    printf("error: [w] region for %zx not found\n", addr);
#endif
    return false;
  }

  if (!region->writable) {
#ifdef TEST_VERBOSE
    printf("error: [w] region for %zx read-only\n", addr);
#endif
    return false;
  }

  if (addr + size > region->start + region->size) {
#ifdef TEST_VERBOSE
    printf("error: [w] region for %zx too small\n", addr);
#endif
    return false;
  }

  size_t idx = addr - region->start;
  memcpy(region->mem + idx, src, size);
  return true;
}

bool rv_mem_read(rv_ctx_t *ctx, size_t addr, void *dst, size_t size) {
  // Note: Missing support for cross-region reads. Missing signal support.
  rv_mem_region_t *region = rv_mem_translate(ctx, addr);
  if (region == NULL) {
#ifdef TEST_VERBOSE
    printf("error: [r] region for %zx not found\n", addr);
#endif
    return false;
  }

  if (addr + size > region->start + region->size) {
#ifdef TEST_VERBOSE
    printf("error: [r] region for %zx roo small\n", addr);
#endif
    return false;
  }

  size_t idx = addr - region->start;
  memcpy(dst, region->mem + idx, size);
  return true;
}

static bool rv_execute_instruction_base(
  rv_ctx_t *ctx, rv_opcode_info_t *info, uint32_t opcode) {

  ctx->pc += 4;
  uint8_t tmp8 = 0;
  uint16_t tmp16 = 0;
  uint32_t tmp32 = 0;
  uint64_t tmp64 = 0;
  uint64_t addr = 0;

  (void)tmp16;  // Ignore unused warning.

  switch (info->opcode) {
    case 0x03:  // 0000011
      rv_decode_I(info, opcode);
      switch (info->funct) {
        case 2: // 010 LW
          addr = ctx->x[info->rs1] + (int32_t)info->imm;
          if (!rv_mem_read(ctx, addr, &tmp32, 4)) {
            return false;
          }
          ctx->x[info->rd] = tmp32;
#ifdef TEST_VERBOSE
          printf("lw x%u, dword [0x%zx]\n", info->rd, addr);
#endif
          return true;

        case 4: // 100 LBU
          addr = ctx->x[info->rs1] + (int32_t)info->imm;
          if (!rv_mem_read(ctx, addr, &tmp8, 1)) {
            return false;
          }
          ctx->x[info->rd] = tmp8;
#ifdef TEST_VERBOSE
          printf("lbu x%u, byte [0x%zx]\n", info->rd, addr);
#endif
          return true;
      }
      break;

    case 0x13:  // 0010011
      switch (info->funct) {
        case 0x0: // 000 ADDI
          rv_decode_I(info, opcode);
          ctx->x[info->rd] = ctx->x[info->rs1] + (int32_t)info->imm;
#ifdef TEST_VERBOSE
          printf("addi x%u, x%u, 0x%x\n", info->rd, info->rs1, info->imm);
#endif
          return true;

        case 0x1: { // 001 SLLI
          uint32_t top = BITFIELD(opcode, 26, 31);
          uint32_t shamt = BITFIELD(opcode, 20, 25);
          rv_decode_I(info, opcode);

          if (top == 0) {
            ctx->x[info->rd] = ctx->x[info->rs1] << shamt;
#ifdef TEST_VERBOSE
            printf("slli x%u, x%u, %u\n", info->rd, info->rs1, shamt);
#endif
            return true;
          }
        }
        break;

        case 0x3: // 011 SLTIU
          rv_decode_I(info, opcode);
          ctx->x[info->rd] = (ctx->x[info->rs1] < info->imm);
#ifdef TEST_VERBOSE
          printf("sltiu x%u, x%u, 0x%x\n", info->rd, info->rs1, info->imm);
#endif
          return true;

        case 0x5: { // 101 SRLI
          uint32_t top = BITFIELD(opcode, 26, 31);
          uint32_t shamt = BITFIELD(opcode, 20, 25);
          rv_decode_I(info, opcode);

          if (top == 0) {
            ctx->x[info->rd] = ctx->x[info->rs1] >> shamt;
#ifdef TEST_VERBOSE
            printf("srli x%u, x%u, %u\n", info->rd, info->rs1, shamt);
#endif
            return true;
          }
        }
        break;

        case 0x7: // 111 ANDI
          rv_decode_I(info, opcode);
          ctx->x[info->rd] = ctx->x[info->rs1] & (int32_t)info->imm;
#ifdef TEST_VERBOSE
          printf("andi x%u, x%u, 0x%x\n", info->rd, info->rs1, info->imm);
#endif
          return true;

      }
      break;

    case 0x1B:  // 0011011
      rv_decode_I(info, opcode);

      if (info->funct == 0) {
        tmp32 = ctx->x[info->rs1] + (int32_t)info->imm;
        tmp64 = tmp32;
        ctx->x[info->rd] = SIGNEXT(tmp64, 31);
#ifdef TEST_VERBOSE
        printf("addiw x%u, x%u, 0x%x\n", info->rd, info->rs1, info->imm);
#endif
        return true;
      } else {  // Not ADDIW
        // This is somewhat of a special case.
        uint32_t top = BITFIELD(opcode, 25, 31);
        uint32_t shamt = BITFIELD(opcode, 20, 24);

        tmp32 = ctx->x[info->rs1];

        if (info->funct == 1 /* 001 */ && top == 0 /* 0000000 */) {
          // SLLIW
          tmp32 = tmp32 << shamt;
          ctx->x[info->rd] = SIGNEXT(tmp32, 31);
#ifdef TEST_VERBOSE
          printf("slliw x%u, x%u, %u\n", info->rd, info->rs1, shamt);
#endif
          return true;
        }

        if (info->funct == 5 /* 101 */ && top == 0 /* 0000000 */) {
          // SRLIW
          tmp32 = tmp32 >> shamt;
          ctx->x[info->rd] = SIGNEXT(tmp32, 31);
#ifdef TEST_VERBOSE
          printf("srliw x%u, x%u, %u\n", info->rd, info->rs1, shamt);
#endif
          return true;
        }


      }
      break;

    case 0x23:  // 0100011 Sx
      rv_decode_S(info, opcode);
      switch (info->funct) {
        case 0x0: // 000 SB
          tmp8 = (uint8_t)ctx->x[info->rs2];
          addr = ctx->x[info->rs1] + (int32_t)info->imm;
          if (!rv_mem_write(ctx, addr, &tmp8, 1)) {
            return false;
          }
#ifdef TEST_VERBOSE
          printf("sb x%u, byte [0x%zx]\n", info->rs2, addr);
#endif
          return true;

        case 0x2: // 010 SW
          tmp32 = (uint32_t)ctx->x[info->rs2];
          addr = ctx->x[info->rs1] + (int32_t)info->imm;
          if (!rv_mem_write(ctx, addr, &tmp32, 4)) {
            return false;
          }
#ifdef TEST_VERBOSE
          printf("sw x%u, dword [0x%zx]\n", info->rs2, addr);
#endif
          return true;

        case 0x3: // 010 SW
          tmp64 = ctx->x[info->rs2];
          addr = ctx->x[info->rs1] + (int32_t)info->imm;
          if (!rv_mem_write(ctx, addr, &tmp64, 8)) {
            return false;
          }
#ifdef TEST_VERBOSE
          printf("sd x%u, qword [0x%zx]\n", info->rs2, addr);
#endif
          return true;

      }
      break;

    case 0x33:  // 0110011
      rv_decode_R(info, opcode);

      switch (info->funct) {
        case 0x000: // 0000000 000 ADD
          ctx->x[info->rd] = ctx->x[info->rs1] + ctx->x[info->rs2];
#ifdef TEST_VERBOSE
          printf("add x%u, x%u, x%u\n", info->rd, info->rs1, info->rs2);
#endif
          return true;

        case 0x100: // 0100000 000 SUB
          ctx->x[info->rd] = ctx->x[info->rs1] - ctx->x[info->rs2];
#ifdef TEST_VERBOSE
          printf("sub x%u, x%u, x%u\n", info->rd, info->rs1, info->rs2);
#endif
          return true;

        case 0x004: // 0000000 100 XOR
          ctx->x[info->rd] = ctx->x[info->rs1] ^ ctx->x[info->rs2];
#ifdef TEST_VERBOSE
          printf("xor x%u, x%u, x%u\n", info->rd, info->rs1, info->rs2);
#endif
          return true;

        case 0x006: // 0000000 110 OR
          ctx->x[info->rd] = ctx->x[info->rs1] | ctx->x[info->rs2];
#ifdef TEST_VERBOSE
          printf("or x%u, x%u, x%u\n", info->rd, info->rs1, info->rs2);
#endif
          return true;
      }
      break;


    case 0x37:  // 0110111 LUI
      rv_decode_U(info, opcode);
      ctx->x[info->rd] = info->imm;
#ifdef TEST_VERBOSE
      printf("lui x%u, 0x%x\n", info->rd, info->imm);
#endif
        return true;

    case 0x3B:  // 0111011
      rv_decode_R(info, opcode);
      switch (info->funct) {
        case 0x000: // 0000000 000 ADDW
          tmp32 = ctx->x[info->rs1] + ctx->x[info->rs2];
          tmp64 = tmp32;
          tmp64 = SIGNEXT(tmp64, 31);
          ctx->x[info->rd] = tmp64;
#ifdef TEST_VERBOSE
          printf("addw x%u, x%u, x%u\n", info->rd, info->rs1, info->rs2);
#endif
          return true;

        case 0x001: // 0000000 001 SLLW
          tmp32 = (uint32_t)ctx->x[info->rs1] << (ctx->x[info->rs2] & 0x1f);
          tmp64 = tmp32;
          tmp64 = SIGNEXT(tmp64, 31);
          ctx->x[info->rd] = tmp64;
#ifdef TEST_VERBOSE
          printf("sllw x%u, x%u, x%u\n", info->rd, info->rs1, info->rs2);
#endif
        return true;

        case 0x105: // 0100000 101 SRAW
          tmp32 = (int32_t)ctx->x[info->rs1] >> (ctx->x[info->rs2] & 0x1f);
          tmp64 = tmp32;
          tmp64 = SIGNEXT(tmp64, 31);
          ctx->x[info->rd] = tmp64;
#ifdef TEST_VERBOSE
          printf("sraw x%u, x%u, x%u\n", info->rd, info->rs1, info->rs2);
#endif
        return true;
      }
      break;

    case 0x63: // 1100011 Bxx
      rv_decode_B(info, opcode);
      switch (info->funct) {
        case 0:  // 000 BEQ
        if (ctx->x[info->rs1] == ctx->x[info->rs2]) {
          ctx->pc -= 4;
          ctx->pc += (int32_t)info->imm;
        }
#ifdef TEST_VERBOSE
        printf("beq x%u, x%u\n", info->rs1, info->rs2);
#endif
        return true;

        case 1:  // 001 BNE
        if (ctx->x[info->rs1] != ctx->x[info->rs2]) {
          ctx->pc -= 4;
          ctx->pc += (int32_t)info->imm;
        }
#ifdef TEST_VERBOSE
        printf("bne x%u, x%u\n", info->rs1, info->rs2);
#endif
        return true;
      }
      break;

    case 0x67: // 1100111 JALR
      if (info->funct != 0) {
        break;
      }

      rv_decode_I(info, opcode);
      addr = ctx->x[info->rs1] + (int32_t)info->imm;
      addr &= ~1ULL;

      ctx->x[info->rd] = ctx->pc;
      ctx->pc = addr;

#ifdef TEST_VERBOSE
        printf("jarl x%u, 0x%zx\n", info->rd, addr);
#endif
      return true;

    case 0x6F: // 1101111 JAL
      rv_decode_UJ(info, opcode);
      addr = ctx->pc - 4 + (int32_t)info->imm;
      ctx->x[info->rd] = ctx->pc;
      ctx->pc = addr;

#ifdef TEST_VERBOSE
        printf("jal x%u, 0x%zx\n", info->rd, addr);
#endif
      return true;
  }

  return false;
};

bool rv_execute_instruction(rv_ctx_t *ctx) {
  uint32_t opcode;
  ctx->zero = 0;  // Make sure zero is zero.

#ifdef TEST_VERBOSE
  printf("%.4x:  ", (uint32_t)ctx->pc);
#endif

  // I'm ignoring the case of RVC opcode on region boundary.
  if (!rv_mem_read(ctx, ctx->pc, &opcode, 4)) {
    return false;
  }

  rv_opcode_info_t info = { 0 };  // Zeroed.
  rv_decode_opportunistic(&info, opcode);

  if ((opcode & 3) == 3) {
    // RISC-V base opcode map.
    bool ret = rv_execute_instruction_base(ctx, &info, opcode);
    ctx->zero = 0;  // Make sure zero is zero.
    return ret;
  } else {
    // RISC-V compressed opcode map.
#ifdef TEST_VERBOSE
    printf("error: unsupported compressed opcode\n");
#endif
  }

  // Should never get here, unless speculative execution or sth.
  return false;
}

void rv_run(rv_ctx_t *ctx, size_t start_pc) {
  ctx->pc = start_pc;
  while(rv_execute_instruction(ctx)) {
    // Keep going.
  }

#ifdef TEST
  puts("stop");
  printf("pc: 0x%zx\n", ctx->pc);
  for (int i = 0; i < 32; i++) {
    printf("x%-2i: 0x%-16zx    ", i, ctx->x[i]);
    if ((i + 1) % 4 == 0) {
      putchar('\n');
    }
  }
#endif
}

#ifndef TEST
#include "checker_as_mem.c"
uint8_t stack[0x1000];

bool rv_checker(void *flag) {
  uint64_t flag_offset = sizeof(mem) - 0x20;
  memcpy(mem + flag_offset, flag, 0x1f);

  // Setup environment.
  const uint64_t region_start_offset = 0x1000;
  const uint64_t stack_start_offset = 0x40000;

  rv_ctx_t ctx;
  rv_init(&ctx);
  rv_mem_add(&ctx, mem, region_start_offset, sizeof(mem), true);
  rv_mem_add(&ctx, stack, stack_start_offset, sizeof(stack), true);
  ctx.a[0] = region_start_offset + flag_offset;  // Argument 1
  ctx.sp = stack_start_offset + sizeof(stack) / 2;

  // Go.
  rv_run(&ctx, 0x1000);

  if (ctx.pc == 0) {
    return (bool)ctx.a[0];
  }

  return false;
}
#endif

#ifdef TEST
#include <stdio.h>
#include <string.h>

static bool load_data(void *dst, size_t sz, const char *fname) {
  FILE *f = fopen(fname, "rb");
  if (f == NULL) {
    return false;
  }
  fread(dst, 1, sz, f);
  fclose(f);

  return true;
}

uint8_t mem[10 * 0x1000];
uint8_t stack[0x1000];

int main() {
  if (!load_data(mem, sizeof(mem), "checker.flat")) {
    puts("file not found");
    return 1;
  }

  // Copy a test string.
  uint64_t addr = sizeof(mem) - 0x20;
  memcpy(mem + addr, "flag{APrettyRiskvTask}", 22);

  // Setup environment.
  const uint64_t region_start_offset = 0x1000;
  const uint64_t stack_start_offset = 0x40000;
  rv_ctx_t ctx;
  rv_init(&ctx);
  rv_mem_add(&ctx, mem, region_start_offset, sizeof(mem), true);
  rv_mem_add(&ctx, stack, stack_start_offset, sizeof(stack), true);
  ctx.a[0] = addr + region_start_offset;
  ctx.sp = stack_start_offset + sizeof(stack) / 2;

  // Go.
  rv_run(&ctx, 0x1000);

  printf("ret: 0x%zx\n", ctx.a[0]);

  /*printf("%.8x\n", SIGNEXT(0, 0));
  printf("%.8x\n", SIGNEXT(1, 0));
  printf("%.8x\n", SIGNEXT(5, 2));
  printf("%.8x\n", SIGNEXT(3, 2));*/

  /*for (int i = 0; i < 32; i++) {
    printf("%u,", stack[0x800 - 0x20 + i]);
  }
  putchar('\n');*/

  if (ctx.a[0] == 1 && ctx.pc == 0) {
    puts("RISC-V works");
    return 0;
  }

  puts("RISC-V problem");
  return 1;
}
#endif

