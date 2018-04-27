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



#include "str.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

Str createStr(char *data, int length) {
  Str s = malloc(sizeof (struct str));
  s->data = malloc(length);
  memcpy(s->data, data, length);
  s->length = length;
  return s;
}

Str createStrFromInt(long long v) {
  char *buf = malloc(25);
  sprintf(buf, "%lld", v);
  Str s = createStr(buf, strlen(buf));
  free(buf);
  return s;
}

Str createStrFromRange(Str s, int start, int end) {
  return createStr(&s->data[start], end - start);
}

Str cloneStr(Str s) {
  return createStr(s->data, s->length);
}

void freeStr(Str s) {
  free(s->data);
  free(s);
}

Str combineStr(Str s1, Str s2) {
  Str s = malloc(sizeof (struct str));
  s->data = malloc(s1->length + s2->length);
  memcpy(s->data, s1->data, s1->length);
  memcpy(&s->data[s1->length], s2->data, s2->length);
  s->length = s1->length + s2->length;
  return s;

}

int strEq(Str s1, Str s2) {
  if (s1->length != s2->length) {
    return 0;
  }
  return !memcmp(s1->data, s2->data, s1->length);
}
