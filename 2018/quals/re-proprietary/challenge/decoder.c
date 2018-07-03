/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>

#define MAX_SIZE        2048
                        // GCTF
#define HEADER          0x46544347

struct rgb {
  unsigned char r, g, b;
};

int width, height;
struct rgb data[MAX_SIZE][MAX_SIZE];

void encodeInt(unsigned int num, int size) {
  int i;
  for (i = 0; i < size; i++) {
    printf("%c", num & 0xff);
    num >>= 8;
  }
}

unsigned int readInt(int size) {
  int i;
  unsigned int res = 0;
  for (i = 0; i < size; i++) {
    unsigned char c;
    scanf("%c", &c);
    res += (c << (8 * i));
  }
  return res;
}

int getColorInt(struct rgb c) {
  return (c.r << 16) + (c.g << 8) + c.b;
}

struct rgb fromColorInt(int c) {
  struct rgb res;
  res.r = c >> 16;
  res.g = (c >> 8) & 0xff;
  res.b = c & 0xff;
  return res;
}

void decodeQuad(int xMin, int xMax, int yMin, int yMax) {
  int v = readInt(1);
  if (v != 15) {
    unsigned int c = readInt(3);
    int i, j;
    for (i = yMin; i < yMax; i++) {
      for (j = xMin; j < xMax; j++) {
        data[i][j] = fromColorInt(c);
      }
    }
  }
  int xMid = (xMin + xMax) / 2;
  int yMid = (yMin + yMax) / 2;
  if (v & 1) {
    decodeQuad(xMin, xMid, yMin, yMid);
  }
  if (v & 2) {
    decodeQuad(xMid, xMax, yMin, yMid);
  }
  if (v & 4) {
    decodeQuad(xMin, xMid, yMid, yMax);
  }
  if (v & 8) {
    decodeQuad(xMid, xMax, yMid, yMax);
  }
}

int main() {
  unsigned int header = readInt(4);
  if (header != HEADER) {
    fprintf(stderr, "Invalid header\n");
    exit(1);
  }
  int width = readInt(4);
  int height = readInt(4);
  if (width <= 0 || width > MAX_SIZE || height <= 0 || height > MAX_SIZE) {
    fprintf (stderr, "Invalid image\n");
    exit(1);
  }
  int n = 0;
  for (n = 0; (1 << n) < width || (1 << n) < height; n++);
  decodeQuad(0, 1 << n, 0, 1 << n);
  printf("P6\n%d %d\n255\n", width, height);
  int i, j;
  for (i = 0; i < height; i++) {
    for (j = 0; j < width; j++) {
      printf("%c%c%c", data[i][j].r, data[i][j].g, data[i][j].b);
    }
  }
  return 0;
}
