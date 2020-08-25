/*
 * Copyright 2020 Google LLC
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

#include "internal.h"

static void *memcpy(void *dst, const void *src, unsigned long len) {
  asm volatile(
    "rep movsb\n\t"
  : //out
    "+D"(dst),
    "+S"(src),
    "+c"(len)
  : //in
  : //clobber
    "cc", "memory"
  );
  return dst;
}

int gatekey_open(char *path, char *authkey) {
  struct gatekey_args args = {
    .op = GATEKEY_OP_OPEN,
    .path = path
  };
  memcpy(&args.authkey, authkey, 64);
  return gatekey_call(&args);
}

int gatekey_create(char *path, char *authkey_out) {
  struct gatekey_args args = {
    .op = GATEKEY_OP_CREATE,
    .path = path
  };
  int res = gatekey_call(&args);
  memcpy(authkey_out, &args.authkey, 64);
  return res;
}
