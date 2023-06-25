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

#include "board.h"

// Start close to the top-left corner.
#define SX 30
#define SY 30
int x = SX;
int y = SY;
//int stepno = 0;

unsigned int dir = 0;

//              U  R  D   L
int dirx[4] = { 0, 1, 0, -1};
int diry[4] = {-1, 0, 1,  0};

//#define VERT 25
#define VERT 35

#define BOARD(i, j) ((board[(i)][(j) / 8] >> ((j)%8)) & 1)
#define XOR_BOARD(i, j) board[(i)][(j) / 8] ^= 1 << ((j)%8)
#define XOR_BOARD2(i, j) board[(i)][(j) / 8] ^= 3 << ((j)%8)

/*
void print_board() {
  static int px, py;
  if (x > px + 27 || x < px - 27) px = x;
  if (y > py + 22 || y < py - 22) py = y;
  for (int i = py - VERT; i <= py + VERT; i++) {
    for (int j = px - 30; j <= px + 30; j++) {
      if (i == y && j == x) {
        printf("%c", "urdlURDL"[dir + BOARD(i,j) * 4]);
        printf("%c", "urdlURDL"[dir + BOARD(i,j) * 4]);
      }
      else {
        if (BOARD(i,j)) {
          printf("██");
        }
        else {
          printf("  ");
        }
      }
    }
    printf("\n");
  }
  printf("step: %d, x %d, y %d, dir %c\n", stepno, x, y, "URDL"[dir]);
  printf("---\n");
}
*/

void step() {
  //stepno++;
  XOR_BOARD(y, x);
  dir += 1 - BOARD(y,x) * 2;
  dir &= 3;
  y += diry[dir];
  x += dirx[dir];
  if (x < 0 || y < 0 || x >= SZX || y >= SZY) {
    printf("out\n");
    exit(1);
  }
}

int main() {
  printf("=== Flangton checker ===\n");
  printf("Enter flag:\n");
  char flag[256];
  scanf("%25s", flag);
  for (int i = 0; flag[i]; i++) {
    for (int j = 0; j < 7; j++) {
      if (flag[i] & (1<<(6-j))) {
        XOR_BOARD2(50, 218+168*(i*7+j));
      }
    }
  }

  for (;;) {
    step();
    /*
    if (x == 98 + 28 * CIRCUIT_WIDTH && y % 50 == 5) {
      printf("DBG: % 5d: ", y/50);
      int i = y / 50;
      for (int j = 0; j < CIRCUIT_WIDTH; j++) {
        printf("%d", BOARD(50+50*i,106+28*j));
      }
      printf("\nDBG:        %s\n", circuit[i]);
    }
    */
    if (EXIT_COND) {
      int last_bit = BOARD(50+50*CIRCUIT_HEIGHT, 106+28*0);
      printf("Flag: %s!\n", "invalid\0correct" + last_bit*8);
      //printf("DBG: %d\n", last_bit);
      break;
    }
  }

}
