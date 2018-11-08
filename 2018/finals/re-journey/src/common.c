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

// Common functions.

void my_strcpy(char *dst, const char *src) {
  while (*src) {
    *dst++ = *src++;
  }
  *dst = '\0';
}

int my_strlen(const char *src) {
  int count = 0;
  while (*src++) count++;
  return count;
}

#ifdef SPARC
void *memset(void *s, int c, unsigned long n) {
  char *ss = s;
  for (unsigned long i = 0; i < n; i++) {
    ss[i] = c;
  }
  return s;
}

void *memcpy(void *dest, const void *src, unsigned long n) {
  char *d = dest;
  const char *s = src;
  for (unsigned long i = 0; i < n; i++) {
    d[i] = s[i];
  }
  return dest;
}

#endif

