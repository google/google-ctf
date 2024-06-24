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

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

int main() {
  char path[256];
  int fd = -1;
  for (int i = 0; i < 200; ++i) {
    sprintf(path, "/proc/%d/cmdline", i);
    fd = open(path, O_RDONLY);
    if (fd == -1) {
      continue;
    }
    char flag[256];
    int r = read(fd, flag, 256);
    flag[r] = '\0';
    for (int j = 0 ; j < r; ++j) {
      if (!flag[j]) {
        flag[j] = ' ';
      }
    }
    printf("Cmd line: %s\n", flag);
    if (strstr(flag, "CTF") != nullptr) { 
      printf("Flag is: %s\n", flag);
      break;
    }
  }
}
