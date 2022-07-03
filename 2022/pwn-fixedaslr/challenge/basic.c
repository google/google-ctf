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
#include "syscalls.h"
#include "basic.h"

int strcmp(const char *a, const char *b) {
  for (;;) {
    if (*a != *b) {
      return *a - *b;
    }

    if (*a == '\0') {
      return 0;
    }

    a++; b++;
  }
}

char *strcpy(char *dst, const char *src) {
  char *org_dst = dst;
  do {
    *dst++ = *src;
  } while (*src++);
  return org_dst;
}

size_t strlen(const char *s) {
  size_t i = 0;
  while (*s++) i++;
  return i;
}

uint64_t read(int fd, void *dst, uint64_t sz) {
  return sys_read(fd, dst, sz);
}

void print(const char *s) {
  sys_write(1, s, strlen(s));
}

int puts(const char *s) {
  sys_write(1, s, strlen(s));
  sys_write(1, "\n", 1);
  return 0;
}

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

uint64_t atou64(const char *s) {
  uint64_t n = 0ULL;
  while (*s) {
    if (*s >= '0' && *s <= '9') {
      n *= 10ULL;
      n += *s++ - '0';
    } else {
      break;
    }
  }
  return n;
}

int getchar(void) {
  char ch;
  if (sys_read(0, &ch, 1) != 1) {
    return -1;
  }
  return ch;
}

void __attribute__ ((noreturn)) exit(int code) {
  sys_exit(code);
}

uint32_t rand(void) {
  uint32_t v;
  sys_getrandom(&v, 4, /*flags=*/2);
  return v;
}
