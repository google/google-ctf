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

int main() {
  // NOTE: there is no srand set yet.

  while (true) {
    emu8051 emu;
    uint8_t pmem_image[0x100];
    for (size_t i = 0; i < sizeof(pmem_image); i++) {
      pmem_image[i] = rand();
    }

    emu.mem_write(emu8051::mem_type_t::PMEM, /*addr=*/0, pmem_image, sizeof(pmem_image));
    emu.execute(1000);
    putchar('.');
  }

  return 0;
}


