/*
 * Copyright 2018 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



/**
 * This solution takes about 6 minutes to run, and uses about 1GB of RAM.
 * You have been warned.
 */
#include <stdio.h>
#include <stdlib.h>

#define JUMP_SIZE     25
#define TABLE_SIZE    (1 << JUMP_SIZE)
#define LIMIT         (1llu << 62)

typedef unsigned long long ull;

struct det {
  ull amoOdd;
  ull resApply;
};

ull findTotalHailstone(ull upto) {
  struct det *results = malloc(sizeof (struct det) * TABLE_SIZE);
  ull *pow3 = malloc(sizeof (ull) * (JUMP_SIZE + 1));
  ull *smallValCache = malloc(sizeof (ull) * TABLE_SIZE);
  if (results == NULL || pow3 == NULL || smallValCache == NULL) {
    printf ("Ran out of memory\n");
    exit(1);
  }
  ull i, j;
  pow3[0] = 1;
  smallValCache[0] = 0;
  for (i = 1; i <= JUMP_SIZE; i++) {
    pow3[i] = 3 * pow3[i - 1];
  }
  for (i = 0; i < TABLE_SIZE; i++) {
    ull at = i;
    ull oddsE = 0;
    for (j = 0; j < JUMP_SIZE; j++) {
      if (at & 1) {
        oddsE++;
        at += (at + 1) / 2;
      } else {
        at /= 2;
      }
      if (at > LIMIT) {
        printf ("BAD LIMIT\n");
        exit(1);
      }
    }
    results[i].amoOdd = oddsE;
    results[i].resApply = at;
  }
  for (i = 1; i < TABLE_SIZE; i++) {
    ull at = i;
    ull c = 0;
    while (at != 1) {
      if (at & 1) {
        at += (at + 1) / 2;
        c += 2;
      } else {
        at /= 2;
        c++;
      }
      if (at < i) {
        c += smallValCache[at];
        break;
      }
      if (at > LIMIT) {
        printf ("BAD LIMIT\n");
        exit(1);
      }
    }
    smallValCache[i] = c;
  }
  ull total = 0;
  for (i = 1; i <= upto; i++) {
    ull c = 0;
    ull at = i;
    while (1) {
      if (at < TABLE_SIZE) {
        c += smallValCache[at];
        break;
      }
      ull p = at & (TABLE_SIZE - 1);
      c += JUMP_SIZE + results[p].amoOdd;
      at = (at >> JUMP_SIZE) * pow3[results[p].amoOdd] + results[p].resApply;
      if (at > LIMIT) {
        printf ("BAD LIMIT\n");
        exit(1);
      }
    }
    total += c;
  }
  return total;
}

ull findFib(ull n, ull mod) {
  ull a = 0;
  ull b = 1;
  ull i;
  if (n < 2) return n;
  for (i = 2; i <= n; i++) {
    ull c = (a + b) % mod;
    a = b;
    b = c;
  }
  return b;
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf ("Expecting number\n");
    return 1;
  }
  ull n = atoll(argv[1]);
  ull totalH = findTotalHailstone(n);
  ull fibR = findFib(n, totalH);
  printf ("CTF{%016llx}\n", fibR);
  return 0;
}
