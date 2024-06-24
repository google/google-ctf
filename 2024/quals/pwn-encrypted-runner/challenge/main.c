// Copyright 2024 Google LLC
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
#include <string.h>
#include <stdint.h>

#include "aes.h"

int main(void) {
  char key[16] = {0};
  FILE* f = fopen("key", "rb");
  if (!f) {
    fprintf(stderr, "Could not open key file.\n");
    return 1;
  }
  if (16 != fread(key, 1, 16, f)) {
    fprintf(stderr, "Could not read key file.\n");
    return 1;
  }
  fclose(f);

  char mode[100];
  scanf("%s", mode);

  uint32_t data[16];
  for (int i = 0; i < 16; i++) {
    scanf("%x", &data[i]);
  }

  struct AES_ctx ctx;
  AES_init_ctx(&ctx, key);

  if (!strcmp(mode, "encrypt")) {
    AES_ECB_encrypt(&ctx, data);
  }
  else if (!strcmp(mode, "decrypt")) {
    AES_ECB_decrypt(&ctx, data);
  }

  for (int i = 0; i < 16; i++) {
    printf("%02x ", data[i]);
  }
  printf("\n");
}
