// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
  if (argc != 4) {
    printf("Usage: %s Give flag please\n", argv[0]);
    return 1;
  }
  if (!strcmp(argv[1], "Give") && !strcmp(argv[2], "flag") && !strcmp(argv[3], "please")) {
    printf("CTF{Sh3b4ng_1nj3cti0n_ftw}\n");
  }
}
