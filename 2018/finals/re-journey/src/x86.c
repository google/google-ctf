// Copyright 2018 Google LLC
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
#include <stdint.h>

#include "consts_x86.h"

#include "common.c"

// Assuming dst is zeroed.
static void mixer(uint8_t *dst, const uint8_t *src) {
  for (int i = 0; i < 32 * 8; i++) {
    uint16_t src_idx = MIXER[i] >> 1;
    uint16_t src_bit = src_idx % 8;
    uint16_t src_byte = src_idx / 8;

    uint8_t bit = (src[src_byte] >> src_bit) & 1;

    if (MIXER[i] & 1) {
      bit ^= 1;
    }

    uint16_t dst_bit = i % 8;
    uint16_t dst_byte = i / 8;

    dst[dst_byte] |= bit << dst_bit;
  }
}

#ifndef TEST
__attribute__((section(".start")))
#endif
void checker(char *input, char *output) {
  uint8_t mixed[32] = {0};
  mixer(mixed, (uint8_t*)input);

  uint8_t test = 0;
  for (int i = 0; i < 32; i++) {
    test |= mixed[i] ^ CONSTS[i];
  }

  if (test) {
    my_strcpy(output, "error: wrong password, X86 journey not completed");
  } else {
    my_strcpy(output, "X86 journey completed");
  }
}

#include "tester.c"

