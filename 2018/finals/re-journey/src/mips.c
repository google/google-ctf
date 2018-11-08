#include <stdint.h>
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

#include "consts_mips.h"

#include "common.c"

uint64_t x = 0, w = 0, s = 0xb5ad4eceda1ce2a9;

// https://en.wikipedia.org/wiki/Middle-square_method
static uint32_t msws(void) {
  x *= x;
  w += s;
  x += w;
  x = (x >> 32) | (x << 32);
  return x;
}

static void encrypt(void *data, int length) {
  uint8_t *d = data;
  for (int i = 0; i < length; i++) {
    d[i] ^= msws();
  }
}

#ifndef TEST
__attribute__((section(".start")))
#endif
void checker(char *input, char *output) {
  encrypt(input, 32);
  uint8_t test = 0;
  for (int i = 0; i < 32; i++) {
    test |= CONSTS[i] ^ input[i];
  }

  if (test) {
    my_strcpy(output, "error: wrong password, MIPS journey not completed");
  } else {
    my_strcpy(output, "MIPS journey completed");
  }
}

#include "tester.c"

