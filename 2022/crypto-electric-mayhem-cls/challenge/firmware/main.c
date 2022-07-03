// Copyright 2022 Google LLC
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
#include <stdio.h>
#include <stdlib.h>

#include "aes.h"
#include "elmoasmfunctionsdef.h"

static uint32_t N = 1;
static uint8_t key[16] = {};
static uint8_t in[16] = {};

int main() {
  // Read #traces.
  LoadN(&N);

  // Read key.
  for (uint32_t j = 0; j < sizeof(key); j++) {
    readbyte(&key[j]);
  }

  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);

  for (uint32_t i = 0; i < N; i++) {
    // Read plaintext.
    for (uint32_t j = 0; j < sizeof(in); j++) {
      randbyte(&in[j]);
    }

    // Analyze AES encryption.
    starttrigger();
    AES_ECB_encrypt(&ctx, in);
    endtrigger();

    // Write ciphertext.
    for (uint32_t j = 0; j < sizeof(in); j++) {
      printbyte(&in[j]);
    }
  }

  endprogram();
  return 0;
}
