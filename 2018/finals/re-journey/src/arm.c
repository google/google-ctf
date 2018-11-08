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

#include "consts_arm.h"

#include "common.c"

static uint32_t hash32(uint32_t v) {
  const uint32_t prime1 = 1043845471;
  const uint32_t prime2 = 2031611221;
  const uint32_t prime3 = 3304597063;
  return (v * prime1 + prime3) % prime2;
}

#ifndef TEST
__attribute__((section(".start")))
#endif
void checker(char *input, char *output) {
  uint32_t test = 0;
  for (int i = 0; i < 32; i++) {
    test |= hash32((uint32_t)input[i]) ^ CONSTS[i];
  }

  if (test) {
    my_strcpy(output, "error: wrong password, ARM journey not completed");
  } else {
    my_strcpy(output, "ARM journey completed");
  }
}

#include "tester.c"

