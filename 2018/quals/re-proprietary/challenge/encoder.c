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
#include <string.h>

#define MAX_SIZE   2048
                   // GCTF
#define HEADER     0x46544347
// This is how close colours can be to be ignored and compressed. Higher means
// higher compression.
#define FACTOR     1000

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

int getDiff(int c1, int c2) {
  struct rgb r1 = fromColorInt(c1);
  struct rgb r2 = fromColorInt(c2);
  int rD = r1.r - r2.r;
  int gD = r1.g - r2.g;
  int bD = r1.b - r2.b;
  return rD * rD + gD * gD + bD * bD;
}

void sort(int s, int e, int* a, int *t) {
  if (e - s <= 1) {
    return;
  }
  int m = (s + e) / 2;
  sort(s, m, a, t);
  sort(m, e, a, t);
  int i;
  int p1 = s;
  int p2 = m;
  for (i = 0; i < e - s; i++) {
    if (p2 >= e || (p1 < m && a[p1] < a[p2])) {
      t[i] = a[p1++];
    } else {
      t[i] = a[p1++];
    }
  }
  for (i = 0; i < e - s; i++) {
    a[s + i] = t[i];
  }
}

int findBestColor(int xMin, int xMax, int yMin, int yMax) {
  // Find most common.
  int *used = malloc(sizeof(int) * (xMax - xMin) * (yMax - yMin));
  int *temp = malloc(sizeof(int) * (xMax - xMin) * (yMax - yMin));
  int i, j;
  int count = 0;
  for (i = yMin; i < yMax; i++) {
    for (j = xMin; j < xMax; j++) {
      used[count++] = getColorInt(data[i][j]);
    }
  }
  sort(0, count, used, temp);
  int best = 0;
  int bestC = 0;
  for (i = 0; i < count; i++) {
    int cc = 1;
    int col = used[i];
    while (i < count && used[i] == col) {
      cc++;
      i++;
    }
    if (cc > bestC) {
      bestC = cc;
      best = col;
    }
  }
  free(used);
  free(temp);
  return best;
}

int doesMatch(int xMin, int xMax, int yMin, int yMax, int c) {
  int i, j;
  for (i = yMin; i < yMax; i++) {
    for (j = xMin; j < xMax; j++) {
      int diff = getDiff(c, getColorInt(data[i][j]));
      if (diff > FACTOR) {
        return 0;
      }
    }
  }
  return 1;
}

void encodeQuad(int xMin, int xMax, int yMin, int yMax, int background) {
  int c = findBestColor(xMin, xMax, yMin, yMax);
  int dx[] = {0, 1, 0, 1};
  int dy[] = {0, 0, 1, 1};
  int i;
  int xDiff = (xMax - xMin) / 2;
  int yDiff = (yMax - yMin) / 2;
  int using = 0;
  for (i = 0; i < 4; i++) {
    int sX = xMin + dx[i] * xDiff;
    int eX = xMin + dx[i] * xDiff + xDiff;
    int sY = yMin + dy[i] * yDiff;
    int eY = yMin + dy[i] * yDiff + yDiff;
    if (!doesMatch(sX, eX, sY, eY, c)) {
      using |= (1 << i);
    }
  }
  encodeInt(using, 1);
  if (using != 15) {
    encodeInt(c, 3);
  }
  for (i = 0; i < 4; i++) {
    int sX = xMin + dx[i] * xDiff;
    int eX = xMin + dx[i] * xDiff + xDiff;
    int sY = yMin + dy[i] * yDiff;
    int eY = yMin + dy[i] * yDiff + yDiff;
    if (!doesMatch(sX, eX, sY, eY, c)) {
      encodeQuad(sX, eX, sY, eY, c);
    }
  }
}

void encode() {
  encodeInt(HEADER, 4);
  encodeInt(width, 4);
  encodeInt(height, 4);
  int n = 0;
  for (n = 0; (1 << n) < width || (1 << n) < height; n++);
  encodeQuad(0, 1 << n, 0, 1 << n, -1);

}

void getGoodBuffer(char *buf, int size) {
  fgets(buf, size, stdin);
  while (buf[0] == '#') {
    fgets(buf, size, stdin);
  }
}

int main() {
  char buf[200];
  getGoodBuffer(buf, 200);
  if (strcmp(buf, "P6\n") != 0) {
    printf ("Expected P6 as the header\n");
    exit(1);
  }
  getGoodBuffer(buf, 200);
  if (sscanf(buf, "%d %d", &width, &height) != 2) {
    printf ("Expected width and height\n");
    exit(1);
  }
  int temp = 0;
  getGoodBuffer(buf, 200);
  if (sscanf(buf, "%d\n", &temp) != 1 || temp != 255) {
    printf ("Expected 255\n");
    exit(1);
  }
  if (width <= 0 || height <= 0 || width > MAX_SIZE || height > MAX_SIZE) {
    printf ("Image to big\n");
    exit(1);
  }
  int i, j;
  for (i = 0; i < height; i++) {
    for (j = 0; j < width; j++) {
      char r,g,b;
      scanf("%c%c%c", &r,&g,&b);
      data[i][j].r = r;
      data[i][j].g = g;
      data[i][j].b = b;
    }
  }
  encode();
  return 0;
}
