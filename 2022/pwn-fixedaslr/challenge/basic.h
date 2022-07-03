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
#pragma once
#include <stdint.h>
#ifndef size_t
#  define size_t uint64_t
#endif
#ifndef NULL
#  define NULL ((void*)0)
#endif

extern int strcmp(const char *a, const char *b);
extern char *strcpy(char *dst, const char *src);
extern size_t strlen(const char *s);
extern int puts(const char *s);
extern void print(const char *s);  // puts without \n
extern uint64_t atou64(const char *s);
extern void u64toa(char *p, uint64_t v);
extern int getchar(void);
extern void exit(int code);
extern uint64_t read(int fd, void *dst, uint64_t sz);
extern uint32_t rand(void);
