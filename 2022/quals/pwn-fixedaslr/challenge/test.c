// Copyright 2022 Google LLC
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
//
//
// Just because I don't trust myself, I decided to actually test this function.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

void u64toa(char *p, uint64_t v) {
  // Max 64-bit unsigned int is 18446744073709551615 (20 digits).

#define X(N) if (v >= (N)) { *p++ = '0' + ((v / (N)) % 10ULL); }
  X(10000000000000000000ULL);
  X(1000000000000000000ULL);
  X(100000000000000000ULL);
  X(10000000000000000ULL);
  X(1000000000000000ULL);

  X(100000000000000ULL);
  X(10000000000000ULL);
  X(1000000000000ULL);
  X(100000000000ULL);
  X(10000000000ULL);

  X(1000000000ULL);
  X(100000000ULL);
  X(10000000ULL);
  X(1000000ULL);
  X(100000ULL);

  X(10000ULL);
  X(1000ULL);
  X(100ULL);
  X(10ULL);
#undef X

  *p++ = '0' + (v % 10);
  *p = '\0';
}

int main() {
  uint64_t n = 3;

  while(true) {
    char buf1[64];
    char buf2[64];

    sprintf(buf1, "%lu", n);
    u64toa(buf2, n);

    //printf("%s %s\n", buf1, buf2);

    if (strcmp(buf1, buf2) != 0) {
      puts("broken");
      break;
    }

    n = n * 10 + rand();

    if (rand() % 100 == 10) {
      n %= 1000;
      n += rand() % 1000;
    } else if (rand() % 100 == 10) {
      n %= 10;
      n += rand() % 10;
    }
  }

  return 0;
}
