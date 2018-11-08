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

#include "consts_sparc.h"

#include "common.c"

#include "md5.h"
#include "md5.c"

uint8_t results[32 * 16];

static void cascadeMD5(const char *src) {
  for (int i = 0; i < 32; i++) {
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, src, i+1);
    MD5_Final(results + i * 16, &ctx);
  }
}

#ifndef TEST
__attribute__((section(".start")))
#endif
void checker(char *input, char *output) {
  cascadeMD5(input);

  uint8_t test = 0;
  for (int i = 0; i < 32 * 16; i++) {
    test |= results[i] ^ CONSTS[i];
  }

  if (test) {
    my_strcpy(output, "error: wrong password, SPARC journey not completed");
  } else {
    my_strcpy(output, "SPARC journey completed");
  }
}

#include "tester.c"

