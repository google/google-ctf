// Copyright 2023 Google LLC
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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>

#include "crc.inc"
#include "zlib.h"

#ifdef FULLSIZE
  typedef size_t image_width_t;
  typedef size_t image_double_width_t;

  #define MAX_SIZE 4096
#else
  typedef uint8_t image_width_t;
  typedef uint16_t image_double_width_t;

  #define MAX_SIZE 128
#endif
typedef uint32_t pixel_t;

// https://en.wikipedia.org/wiki/Hilbert_curve

//convert d to (x,y)
void d2xy(image_width_t n, image_double_width_t d, image_width_t *x, image_width_t *y) {
  int rx;
  image_double_width_t t = d;
  *x = *y = 0;
  for (image_width_t s = 1; s < n; s <<= 1) {
    rx = 1 & (t/2);
    if (!(1 & (t ^ rx))) {
      if (rx == 1) {
        *x = s-1 - *x;
        *y = s-1 - *y;
      }
      //Swap x and y
      *x ^= *y;
      *y ^= *x;
      *x ^= *y;
    }
    else {
      *y += s;
    }
    if (rx) {
      *x += s;
    }
    t >>= 2;
  }
}

void write_chunk(uint8_t* data, uint32_t sz, FILE* f) {
  uint32_t sz4 = __builtin_bswap32(sz);
  fwrite(&sz4, 4, 1, f);
  fwrite(data, 1, sz + 4, f);
  uint32_t c = __builtin_bswap32(crc(data, sz + 4));
  fwrite(&c, 4, 1, f);
}

uint8_t filter_none(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur;
}

uint8_t filter_sub(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur - left;
}

uint8_t filter_up(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur - top;
}

uint8_t filter_xor(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur ^ left;
}

uint8_t filter_xor_up(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur ^ top;
}

uint8_t filter_xor_tltl(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur ^ top ^ left ^ topleft;
}

uint8_t filter_sub2(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur - left2;
}

uint8_t filter_sub3(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur - left3;
}

uint8_t filter_xor2(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur ^ left2;
}

uint8_t filter_xor3(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur ^ left3;
}

uint8_t filter_xor123(uint8_t cur, uint8_t left, uint8_t top, uint8_t topleft, uint8_t left2, uint8_t left3) {
  return cur ^ left ^ left2 ^ left3;
}

typedef uint8_t(*filter_fn_t)(uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t);

#define FILTER_CNT 11
uint8_t filter_bytes[FILTER_CNT] = {
  0xe0, 0xe1, 0xe2,
  0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
  1, 2, 0
};
filter_fn_t filter_functions[FILTER_CNT] = {
  filter_xor, filter_xor_up, filter_xor_tltl,
  filter_sub2, filter_sub3, filter_xor2, filter_xor3, filter_xor123,
  filter_sub, filter_up, filter_none
};

size_t put_row_filter(uint8_t* dst, image_width_t sz, pixel_t* row, pixel_t* prev_row, filter_fn_t filter) {
  size_t score = 0;
  dst++; // Skip filter byte.
  for (image_width_t j = 0; j < sz; j++) {
    pixel_t cur = row[j];
    pixel_t left = j==0 ? 0 : row[j-1];
    pixel_t top = prev_row==NULL ? 0 : prev_row[j];
    pixel_t topleft = prev_row==NULL ? 0 : j==0 ? 0 : prev_row[j-1];
    pixel_t left2 = j<=1 ? 0 : row[j-2];
    pixel_t left3 = j<=2 ? 0 : row[j-3];
    for (int k = 16; k >= 0; k -= 8) {
      int c = filter(cur >> k, left >> k, top >> k, topleft >> k, left2 >> k, left3 >> k);
      *dst++ = c;
      if (c < 128) {
        score += c;
      }
      else {
        score += 256 - c;
      }
    }
  }
  return score;
}

uint8_t* put_row(uint8_t* dst, image_width_t sz, pixel_t* row, pixel_t* prev_row) {
  size_t best_score = SIZE_MAX;
  size_t best_filter = 0;

  size_t mn = SIZE_MAX;
  static size_t filter_use_count[FILTER_CNT];
  for (size_t i = 0; i < FILTER_CNT; i++) {
    if (filter_use_count[i] < mn) {
      mn = filter_use_count[i];
    }
  }

  for (size_t i = 0; i < FILTER_CNT; i++) {
    size_t score = put_row_filter(dst, sz, row, prev_row, filter_functions[i]);
    // Sorry, doing this for the CTF fun only...
    score *= pow(1.01, filter_use_count[i] - mn);
    if (score < best_score) {
      best_score = score;
      best_filter = i;
    }
  }
  *dst = filter_bytes[best_filter];
  filter_use_count[best_filter]++;
  //printf("Chose filter %zu\n", *dst);
  put_row_filter(dst, sz, row, prev_row, filter_functions[best_filter]);
  return dst + sz*3ull + 1;
}

int encode(FILE* fin, FILE* fout) {
  char magic[8] = {0};
  fscanf(fin, "%4s", magic);
  if (strncmp(magic, "P3", 2)) {
    printf("Only P3 PPM files (with no comments) are supported at the moment as the input.\n");
    return 1;
  }
  size_t width, height;
  fscanf(fin, "%zu %zu", &width, &height);
  if (width != height || width == 0 || (width & (width-1))) {
    printf("Only 2^n by 2^n size pictures are supported at this time.\n");
    return 1;
  }
  if (width > MAX_SIZE) {
    printf("Why would you want to process such a large picture?\n");
    return 1;
  }
  image_width_t sz = width;
  uint8_t logsz = 63 - __builtin_clzll(sz);
  int depth;
  fscanf(fin, "%d", &depth);
  if (depth != 255) {
    printf("This file is not supported.\n");
    return 1;
  }
  pixel_t* pixels = malloc(sizeof(pixel_t) * sz * sz);
  for (size_t i = 0; i < (image_double_width_t)sz * sz; i++) {
    int r,g,b;
    fscanf(fin, "%d %d %d", &r, &g, &b);
    pixels[i] = (r<<16) | (g<<8) | (b);
  }

  // Reorder.

  pixel_t* aux = malloc(sizeof(pixel_t) * sz * sz);
  image_width_t y = 0, x = 0;
  for (image_double_width_t i = 0; i < (image_double_width_t)sz * sz; i++) {
    d2xy(sz, i, &x, &y);
    aux[i] = pixels[(((image_double_width_t)y) << logsz) | x];
  }

  // Filter.

  size_t cnt = 3ull * sz * sz + sz;
  uint8_t* filtered = malloc(cnt);
  uint8_t* ptr = filtered;
  for (image_double_width_t i = 0; i < sz; i++) {
    ptr = put_row(ptr, sz, aux + (i<<logsz), i==0 ? NULL : aux + ((i-1)<<logsz));
  }

  // Write the PNG file.

  const char hdr[] = "\x89PNG\r\n\x1a\n";
  fwrite(hdr, 8, 1, fout);
  uint8_t ihdr[21] = "IHDR";
  uint32_t sz4 = __builtin_bswap32(sz);
  memcpy(ihdr+4, &sz4, 4);
  memcpy(ihdr+8, &sz4, 4);
  memcpy(ihdr+12,"\x08\x02\x00\xc0\xde", 5); // 8 bit depth, RGB, deflate,
                                             // custom filter, custom interlace

  write_chunk(ihdr, 13, fout);

  size_t compr_sz = compressBound(cnt);
  uint8_t* compressed = malloc(compr_sz + 4);
  memcpy(compressed, "IDAT", 4);
  compress(compressed + 4, &compr_sz, filtered, cnt);
  write_chunk(compressed, compr_sz, fout);

  write_chunk("IEND", 0, fout);

  fclose(fin);
  fclose(fout);

  return 0;
}

void usage(const char* arg) {
  printf("Usage: %s [encode | decode] INFILE OUTFILE\n", arg);
}

int main(int argc, char** argv) {
  if (argc != 4) {
    usage(argv[0]);
    return 1;
  }

  FILE* fin = fopen(argv[2], "rb");
  if (!fin) {
    printf("Could not open %s\n", argv[2]);
    return 1;
  }
  FILE* fout = fopen(argv[3], "wb");
  if (!fout) {
    printf("Could not open %s\n", argv[3]);
    return 1;
  }

  if (!strcmp(argv[1], "encode")) {
    return encode(fin, fout);
  }
  else if (!strcmp(argv[1], "decode")) {
    printf("Please buy PNG 2.0 Pro to enable this functionality...\n");
    return 1;
  }
  else {
    usage(argv[0]);
    return 1;
  }
}
