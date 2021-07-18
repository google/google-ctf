// Copyright 2021 Google LLC
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

#include <sys/mman.h>
#include <unistd.h>

void (*shellcode)();

int main(int argc, char** argv) {
  shellcode = (void(*)()) mmap(
      0 /*=addr*/,
      0x1000 /*=size*/,
      PROT_EXEC | PROT_WRITE | PROT_READ /*=prot*/,
      MAP_PRIVATE | MAP_ANONYMOUS /*=flags*/,
      -1 /*=fd*/,
      0 /*=offset*/);
  read(0, shellcode, 0x1000);
  shellcode();
}
