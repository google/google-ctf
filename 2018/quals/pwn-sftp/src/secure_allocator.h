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

#include <stdlib.h>
#include <time.h>

#define map_base 0x40000000ull
#define map_mask 0x1fffffffull

void __attribute__((constructor)) setup_allocator() {
  void* ptr = mmap((void*)map_base, map_mask + 0x100000, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (ptr != (void*)map_base) {
    abort();
  }
  srand(time(NULL));
}

void* malloc(size_t size) {
	(void)size;
  void* result = (void*)(unsigned long long)(map_base | (unsigned long long)(rand() & map_mask));
  return result;
}

void* realloc(void* ptr, size_t size) {
	(void)size;
  return ptr;
}

void free(void* ptr) {
	(void)ptr;
}