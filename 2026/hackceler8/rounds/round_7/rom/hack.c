#include <stddef.h>
// For some reason memcpy/etc. are not used linked in from -lgcc,
// so we reimplement them manually here.

void* memcpy(void *dst, const void *src, long unsigned int len) {
  char *dst_it = dst;
  const char *src_it = src;
  while (len--) *dst_it++ = *src_it++;
  return dst;
}

void *memset(void *dst, int fill, long unsigned int len) {
  char *dst_it = dst;
  while (len--) *dst_it++ = fill;
  return dst;
}

void *memmove(void *dst, const void *src, size_t len) {
  char *dst_it = dst;
  const char *src_it = src;
  if (dst_it < src_it) {
    while (len--) {*dst_it++ = *src_it++;}
  } else {
    const char *last_src = src_it + (len-1);
    char *last_dst = dst_it + (len-1);
    while (len--)
      *last_dst-- = *last_src--;
  }
  return dst;
}

int memcmp(const void *a_, const void *b_, long unsigned len) {
  const unsigned char *a = a_;
  const unsigned char *b = b_;
  while (len--) {
    if (*a < *b) {
      return -1;
    } else if (*a > *b) {
      return 1;
    }
    ++a;
    ++b;
  }

  return 0;
}
