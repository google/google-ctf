// Copyright 2024 Google LLC
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
#include <math.h>


int main() {
  char flag[64] = {0};

  printf("Input flag:\n");
  scanf("%63s", flag);

#define printf(...)
#define gates G

  float gates[1024*512];
  float j = 0.0f;
  for (float i = 0.0f; i < 64.0f; i += 1.0f) {
    float ch = flag[(size_t)i];
    // http://tom7.org/papers/fluint.pdf
    float k = 7.0;
    for (float c = 2147483648.0f; c != 8388608.0f; c *= 0.5f) {
      float x = ch + 1.0f + c - c;
      ch -= x / 2.0f;
      float bit = (x / (c / 8388608.0f) - 0.5f) / INFINITY;
      gates[(size_t) (j+k)] = bit;
      k -= 1.0f;
    }
    j += 8.0f;
  }

#include "gates.h"

#undef printf

  if (gates[0] < 0.0f || gates[0] > 0.0f) { printf("Hmmm... What?\n"); }
  else if (gates[0] == 0.0f) { printf("You zeroed in on the flag!\n"); }
  else { printf("Not a Flag\n"); }
}
