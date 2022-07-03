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
//
// Some random tests. Feel free to ignore this file.
//
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

struct tokenizer_st {
  char *ptr;
  int replaced;
};

void tokenizer_init(struct tokenizer_st *t, char *str) {
  t->ptr = str;
  t->replaced = 0x7fff;
}

void tokenizer_finish(struct tokenizer_st *t) {
  if (t->replaced != 0x7fff) {
    *t->ptr = (char)t->replaced;
  }
}

char *tokenizer_next(struct tokenizer_st *t) {
  if (t->replaced != 0x7fff) {
    *t->ptr = (char)t->replaced;
  }

  while (*t->ptr == ' ') {
    t->ptr++;
  }

  if (*t->ptr == '\0') {
    return NULL;
  }

  char *token_start = t->ptr;
  for (;;) {
    char ch = *t->ptr;
    if (ch != ' ' && ch != '\0') {
      t->ptr++;
      continue;
    }

    t->replaced = *t->ptr;
    *t->ptr = '\0';
    return token_start;
  }
}

bool run_tokenizer_test() {
  char buf[256];
  char *p = buf;
  memset(buf, 'X', 256);

  int lengths[10];
  for (int i = 0; i < 10; i++) {
    int l = (rand() % 10) - 1;
    if (i == 9) {
      l = -1;
    }

    lengths[i] = l;

    if (l == -1) {
      *p = '\0';
      break;
    }

    for (int j = 0; j < l; j++) {
      *p++ = 'a';
    }
    *p++ = ' ';
  }

  struct tokenizer_st t;
  tokenizer_init(&t, buf);
  int j = 0;
  while (true) {
    if (lengths[j] == -1) {
      if (tokenizer_next(&t) != NULL) {
        tokenizer_finish(&t);
        printf("ERROR: Expected end of tokens in [%s] at %i\n", buf, j);
        return false;
      }
      break;
    }

    if (lengths[j] == 0) {
      j++;
      continue;
    }

    char *token = tokenizer_next(&t);
    int len = strlen(token);
    if (lengths[j] != len) {
      tokenizer_finish(&t);
      printf("ERROR: Wrong length in [%s] at %i\n", buf, j);
      return false;
    }
    j++;
  }

  return true;
}

void test_tokenizer() {
  // Generates N random tests and check if the output is what's expected.
  srand(time(NULL));
  bool all_good = true;
  for (int k = 0; k < 100000; k++) {
    if (!run_tokenizer_test()) {
      all_good = false;
    }
  }

  if (all_good) {
    printf("tokenizer: all good\n");
  }
}

void uint8_to_str(char *buf, uint8_t v) {
  if (v >= 100) {
    *buf++ = '0' + v / 100;
  }

  if (v >= 10) {
    *buf++ = '0' + (v / 10) % 10;
  }

  *buf++ = '0' + v % 10;
  *buf = '\0';
}

void test_uint8_to_str(void) {
  bool all_good = true;
  for (int i = 0; i < 256; i++) {
    char buf[] = "XXXXXX";
    uint8_to_str(buf, (uint8_t)i);

    char buf_libc[10];
    sprintf(buf_libc, "%i", i);

    if (strcmp(buf, buf_libc) != 0) {
      printf("ERROR: [%s]\n", buf);
      all_good = false;
    }
  }

  if (all_good) {
    puts("uint8_to_str: all good");
  }
}

int main(void) {
  test_uint8_to_str();
  test_tokenizer();

  return 0;
}

