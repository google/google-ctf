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

bool exit_flag;

bool sfr_poweroff(
    emu8051 */*emu*/,
    emu8051::access_type_t access_type,
    emu8051::address_type_t /*addr_type*/, uint8_t /*addr*/,
    uint8_t *value) {
  if (access_type == emu8051::access_type_t::READ) {
    *value = 0;
    return true;
  }

  exit_flag = true;
  return true;
}

int main(int argc, char **argv) {

  if (argc != 2) {
    fprintf(stderr, "usage: test <pmem_image>\n");
    return 0;
  }

  emu8051 emu;

  FILE *f = fopen(argv[1], "rb");
  if (f == nullptr) {
    fprintf(stderr, "file not found\n");
    return 1;
  }

  uint8_t pmem_image[0x10000]{};
  size_t ret = fread(pmem_image, 1, sizeof(pmem_image), f);
  fclose(f);

  emu.mem_write(emu8051::mem_type_t::PMEM, /*addr=*/0, pmem_image, ret);
  emu.sfr_register_handler(0xff, sfr_poweroff);

  for (int i = 0; true; i++) {
    printf("PMEM:%.4x\n", emu.pc_get());
    fflush(stdout);

    emu.execute(1);

    if (exit_flag) {
      break;
    }
  }

  puts("done");


  return 0;
}


