// Copyright 2019 Google LLC
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

#include <stdio.h>
#include <stdint.h>
#include <array>
#include "emu8051.h"

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "usage: test <pmem_image>\n");
    return 0;
  }

  emu8051 emu;
  emu.option_update_parity_flag(false);  // Disable parity flag since s51 doesn't handle it.
  emu.option_DA_s51_compatibility(true);
  emu.option_SUBB_s51_compatibility(true);

  FILE *f = fopen(argv[1], "rb");
  if (f == nullptr) {
    fprintf(stderr, "file not found\n");
    return 1;
  }

  uint8_t pmem_image[0x10000]{};
  size_t ret = fread(pmem_image, 1, sizeof(pmem_image), f);
  fclose(f);

  emu.mem_write(emu8051::mem_type_t::PMEM, /*addr=*/0, pmem_image, ret);

  int step_count = 1;
  scanf("%i", &step_count);

  for (int i = 0; i < step_count; i++) {
    emu.execute(1);
    printf("pc: %.4x\n", emu.pc_get());
    printf("regset: ");

    for (int j = 0; j < 8; j++) {
      printf("%.2x ", emu.r_get(j));
    }
    putchar('\n');

    printf("a: %.2x\n", emu.a_get());
    printf("psw: %.2x\n", emu.psw_get());
    printf("dptr: %.4x\n", emu.dptr_get());
    putchar('\n');
  }

  return 0;
}


