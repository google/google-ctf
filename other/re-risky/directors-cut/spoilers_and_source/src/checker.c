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
// To be compiled to RISC-V.
#include <stdbool.h>
#include <stdint.h>

#include "mixer.c"

bool checker(const uint8_t *f) {
  uint8_t output[32] = {0};

  for (unsigned i = 0U; i < 256U; i++) {
    unsigned bit = mix_bits[i] & 7U;
    unsigned byte = mix_bits[i] >> 3U;
    uint8_t b = (f[byte] >> bit) & 1U;
    b ^= mix_flips[i];
    bit = i & 7U;
    byte = i >> 3U;
    output[byte] |= b << bit;
  }

  unsigned int sum = 0;
  for (unsigned i = 0; i < 32; i++) {
    sum += output[i] ^ flag[i];
  }

  return sum == 0;
}

