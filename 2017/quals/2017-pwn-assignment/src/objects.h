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

#define TRUE      1
#define FALSE     0

typedef struct object *Object;

Object createFromInt(long long v);
Object createFromString(char *data, int length);
Object createFromName(char name, Object previous, int shouldCreate);

void printObject(Object o);
void assignObject(Object assignTo, char name, Object assignFrom);
void addObject(Object assignTo, char name, Object o1, Object o2);
