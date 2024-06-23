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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);

// RFC1924
const uint8_t* alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~";
const uint8_t reverse_alphabet[256] = {
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 62, 255, 63, 64, 65, 66, 255, 67, 68, 69, 70, 255, 71, 255, 255,
0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 255, 72, 73, 74, 75, 76,
77, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 255, 255, 255, 78, 79,
80, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50,
51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 81, 82, 83, 84, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
};

#define PUT(c) if (j >= *dstlen) { return 0; } else { dst[j++] = c; }

int encode85(uint8_t* dst, const uint8_t* src, size_t* dstlen, size_t srclen) {
  size_t j = 0;
  for (size_t i = 0; i < srclen; i += 4) {
    size_t quartet;
    if (i + 1 == srclen) {
      quartet = src[i] + (1ull<<32) + (1ull<<24) + (1ull<<16);
    }
    else if (i + 2 == srclen) {
      quartet = src[i+1] * (256u) + src[i] + (1ull<<32) + (1ull << 24);
    }
    else if (i + 3 == srclen) {
      quartet = src[i+2] * (256u * 256u) + src[i+1] * (256u) + src[i] + (1ull<<32);
    }
    else {
      quartet = src[i+3] * (256u * 256u * 256u) + src[i+2] * (256u * 256u) + src[i+1] * (256u) + src[i];
    }
    PUT(alphabet[quartet % 85]);
    quartet /= 85;
    PUT(alphabet[quartet % 85]);
    quartet /= 85;
    PUT(alphabet[quartet % 85]);
    quartet /= 85;
    PUT(alphabet[quartet % 85]);
    quartet /= 85;
    PUT(alphabet[quartet % 85]);
  }
  PUT(0);
  *dstlen = j - 1;
  return 1;
}

int decode85(uint8_t* dst, const uint8_t* src, size_t* dstlen, size_t srclen) {
  size_t j = 0;
  if (srclen % 5 != 0) return 0; // Invalid.
  for (size_t i = 0; i < srclen; i += 5) {
    size_t quartet = 0;
    for (int k = 4; k >= 0; k--) {
      uint8_t decoded = reverse_alphabet[src[i+k]];
      if (decoded == 255u) return 0; // Invalid character.
      quartet *= 85u;
      quartet += decoded;
    }
    //printf("%llx\n", quartet);
    if (quartet >= (1ull<<32) + (1ull<<24) + (1ull<<16) + (1ull<<8)) return 0; // Invalid, empty combination.
    PUT(quartet % 256);
    if (quartet >= (1ull<<32) + (1ull<<24) + (1ull<<16)) continue;
    PUT(quartet >> 8);
    if (quartet >= (1ull<<32) + (1ull<<24)) continue;
    PUT(quartet >> 16);
    if (quartet >= (1ull<<32)) continue;
    PUT(quartet >> 24);
  }
  if (j <= srclen / 5 * 4 - 4) return 0; // Overlong encoding.
  PUT(0);
  *dstlen = j - 1;
  return 1;
}

const char* hex_alphabet = "0123456789abcdef";

int encodehex(uint8_t* dst, const uint8_t* src, size_t* dstlen, size_t srclen) {
  size_t j = 0;
  for (size_t i = 0; i < srclen; i++) {
    PUT(hex_alphabet[src[i] >> 4]);
    PUT(hex_alphabet[src[i] & 0xf]);
  }
  PUT(0);
  *dstlen = j - 1;
  return 1;
}

int decodehex(uint8_t* dst, const uint8_t* src, size_t* dstlen, size_t srclen) {
  if (srclen % 2 != 0) return 0;
  size_t j = 0;
  for (size_t i = 0; i < srclen; i += 2) {
    uint8_t c = 0;
    if (src[i] >= '0' && src[i] <= '9') {
      c |= src[i] - '0';
    }
    else if (src[i] >= 'a' && src[i] <= 'f') {
      c |= src[i] - 'a' + 10;
    }
    else {
      return 0;
    }
    c <<= 4;

    if (src[i+1] >= '0' && src[i+1] <= '9') {
      c |= src[i+1] - '0';
    }
    else if (src[i+1] >= 'a' && src[i+1] <= 'f') {
      c |= src[i+1] - 'a' + 10;
    }
    else {
      return 0;
    }

    PUT(c);
  }
  PUT(0);
  *dstlen = j - 1;
  return 1;
}

int no_op(uint8_t* dst, const uint8_t* src, size_t* dstlen, size_t srclen) {
  size_t j = 0;
  for (size_t i = 0; i < srclen; i += 1) {
    PUT(src[i]);
  }
  PUT(0);
  *dstlen = j - 1;
  return 1;
}

#define COUNT 6

typedef int(*coder_fn)(uint8_t*, const uint8_t*, size_t*, size_t);

const char* fullnames[COUNT] = {"Plaintext", "Hex encoding", "Ascii85 variant", "Base64", "Zlib", "ROT-13"};
const char* names[COUNT] = {"plain", "hex", "a85", "b64", "zlib", "rot13"};
coder_fn encoders[COUNT] = {no_op, encodehex, encode85, NULL, NULL, NULL};
coder_fn decoders[COUNT] = {no_op, decodehex, decode85, NULL, NULL, NULL};

#define ENTRIES 10

struct {
  char* hash;
  char* encodings[COUNT];
} cache[ENTRIES+1]; // No overflow here...

char* safe_malloc(size_t sz) {
  char* ptr = malloc(sz);
  if (!ptr) {
    printf("Malloc failed...\n");
    exit(1);
  }
}

char* sha256(const char* input, size_t len) {
  char sha[32];
  SHA256(input, len, sha);

  char* hex = safe_malloc(65);
  size_t dstlen = 65;
  encodehex(hex, sha, &dstlen, 32);
  return hex;
}

// Yeah, we don't care about memory leaks :) All malloc and not a single free.
void put(char** encodings, const char* name, const char* data, size_t len) {
  char* ptr = safe_malloc(strlen(name) + len + 1);
  memcpy(ptr, name, strlen(name));
  memcpy(ptr + strlen(name), data, len);
  ptr[strlen(name) + len] = 0;
  size_t i;
  // BUG HERE: what if all encodings are used and different than this?
  // Then you overwrite next cache entry's hash!
  for (i = 0; i < COUNT; i++) {
    if (encodings[i] == NULL) break;
    if (!memcmp(ptr, encodings[i], strlen(name) + len)) return;
  }

  encodings[i] = ptr;
}

char* get(char** encodings, const char* name) {
  for (size_t i = 0; i < COUNT; i++) {
    if (encodings[i] == NULL) continue;
    if (!memcmp(encodings[i], name, strlen(name))) return encodings[i] + strlen(name);
  }
  return NULL;
}

void debug_dump() {
  for (size_t i = 0; i < ENTRIES; i++) {
    printf("%d. Hash [%p] %s\n", i, cache[i].hash, cache[i].hash);
    for (size_t j = 0; j < COUNT; j++) {
      printf("  - %d: [%p] %s\n", j, cache[i].encodings[j], cache[i].encodings[j]);
    }
  }
}

void command(char* from, char* to, char* data, int echo) {
  uint8_t plain[1024];
  uint8_t output[1024];
  static size_t robin = 0;

  int found1 = -1;
  int found2 = -1;
  for (size_t i = 0; i < COUNT; i++) {
    if (!strcmp(names[i], from)) found1 = i;
    if (!strcmp(names[i], to)) found2 = i;
  }
  if (found1 == -1) {
    printf("Invalid encoding: %s\n", from);
    return;
  }
  if (found2 == -1) {
    printf("Invalid encoding: %s\n", to);
    return;
  }

  if (decoders[found1] == NULL) {
    printf("Sorry, that decoder is not implemented... Pull requests are welcome!\n");
    return;
  }
  if (encoders[found2] == NULL) {
    printf("Sorry, that encoder is not implemented... Pull requests are welcome!\n");
    return;
  }

  size_t len = 1024;
  int res = decoders[found1](plain, data, &len, strlen(data));
  if (!res) {
    printf("Decoding failed...\n");
    return;
  }

  char* sha = sha256(plain, len);
  // Now try to find that in cache.

  size_t found = -1;
  for (size_t i = 0; i < ENTRIES; i++) {
    if (cache[i].hash && !memcmp(sha, cache[i].hash, 64)) {
      found = i;
    }
  }

  if (found == -1) {
    // Let's clear a "random" entry from cache, then use it.
    found = robin;
    robin = (robin + 1) % ENTRIES;
    cache[found].hash = sha;
    for (size_t i = 0; i < COUNT; i++) {
      cache[found].encodings[i] = NULL;
    }
  }

  // Now we found it. Let's put both the plain, as well as original encoding
  // in the cache if not exists.

  const char* got = get(cache[found].encodings, to);

  put(cache[found].encodings, "plain", plain, len);
  put(cache[found].encodings, from, data, strlen(data));

  if (!got) {
    size_t len2 = 1024;
    res = encoders[found2](output, plain, &len2, len);
    if (!res) {
      printf("Encoding failed...\n");
      return;
    }

    if (echo) {
      printf("Success. Result: %s\n", output);
    }
    put(cache[found].encodings, to, output, len2);
  }
  else {
    if (echo) {
      printf("Serving from cache. Result: %s\n", got);
    }
  }
  if (!echo) {
    printf("*censored*\n");
  }
  //debug_dump();
}

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  char from[32] = {0};
  char to[32] = {0};
  uint8_t data[1024] = {0};

  FILE* f = fopen("/flag", "r");
  if (!f) {
    printf("Could not open flag...\n");
    return 1;
  }
  fscanf(f, "%s", data);
  fclose(f);


  printf("Welcome to the Swiss Knife of Encodings!\n");
  printf("Available encodings:\n");
  for (size_t i = 0; i < COUNT; i++) {
    printf("- %s (%s)\n", fullnames[i], names[i]);
  }
  printf("Example usage:\n");
  printf("$ plain a85 test\n");
  command("plain", "a85", "test", 1);
  printf("\nAnother example:\n");
  printf("$ plain hex CTF{*censored*}\n");
  command("plain", "hex", data, 0);
  printf("\n\n");
  memset(data, 0, 1024);

  // To not waste memory let's limit to 1024 commands (times 256 bytes,
  // times maybe 2 or 3 for overhead, we're under a megabyte).
  for (size_t i = 0; i < 1024; i++) {
    printf("Awaiting command...\n");
    // No overflow here...
    scanf("%20s %20s %256s", from, to, data);

    if (!strcmp(from, "exit")) {
      break;
    }
    command(from, to, data, 1);
  }
  printf("OK, I think that's enough fun... Bye!\n");
  fflush(stdout);
}
