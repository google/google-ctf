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



#ifndef __STR_H__
#define __STR_H__

typedef struct str *Str;

struct str {
  int length;
  char *data;
};

Str createStr(char *data, int length);
Str createStrFromInt(long long v);
Str cloneStr(Str s);
void freeStr(Str s);
Str combineStr(Str s1, Str s2);

#endif
