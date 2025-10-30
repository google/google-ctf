/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
// From libgcc (https://github.com/gcc-mirror/gcc/blob/master/libgcc)
// For some reason they are not used linked in from -lgcc, so we need to
// declare them manually.
void* memcpy(void *dst, const void *src, long unsigned int n) {
	char *dst_ = dst;
	const char *src_ = src;
	while (n--) *dst_++ = *src_++;
}

void *memset(char *s, int c, long unsigned int n) {
	while (n--) *s++ = c;
}


void *
memmove (void *dest, const void *src, size_t len)
{
  char *d = dest;
  const char *s = src;
  if (d < s)
    while (len--)
      *d++ = *s++;
  else
    {
      const char *lasts = s + (len-1);
      char *lastd = d + (len-1);
      while (len--)
        *lastd-- = *lasts--;
    }
  return dest;
}

int memcmp(char *a, char *b, long unsigned n) {
	while (n--) {
		if (*a < *b) return -1;
		if (*a > *b) return 1;
		++a;
		++b;
	}

	return (*a == *b) ? 0 : 1;
}
