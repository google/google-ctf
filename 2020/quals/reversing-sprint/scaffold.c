// Copyright 2020 Google LLC
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
#include <string.h>
#include <sys/mman.h>

const char M[] = "PROG_HERE";

int main() {
  uint16_t* m = mmap((char*)0x4000000, 1<<26, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  memcpy(m, M, sizeof(M));
  uint16_t* arg[10] = {m, m};
  printf("Input password:\n");
  scanf("%255s", m + 0x7000);
  while (arg[0] != m + 0x7fff) {
    sprintf((char*)0x6000000, (char*)arg[0], "", 0, arg + 0, 0x6000000, *arg[1], 
            arg[1], arg + 1, arg[2], arg + 2, arg[3], arg + 3, 
            arg[4], arg + 4, arg[5], arg + 5, arg[6], arg + 6, 
            arg[7], arg + 7, arg[8], arg + 8, arg[9], arg + 9 
           );
  }
  if (m[0x7400]) {
    printf("Flag: %s\n", m + 0x7400);
  }
}

