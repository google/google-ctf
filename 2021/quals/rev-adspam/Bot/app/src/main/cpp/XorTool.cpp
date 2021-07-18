// Copyright 2021 Google LLC
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

#include <string>

#include <stdint.h>

#include "XorTool.h"

// Decryption key, simple multi-byte XOR.
constexpr int8_t key[] = "cFUgdW9ZIGV2aUcgYW5ub0cgcmV2ZU4=";
constexpr int key_len = sizeof(key) - 1;

std::string DoXor (const char* ciphertext, int len) {
    std::string text;
    for (int i = 0; i < len; ++i) {
        text += key[i%key_len] ^ ciphertext[i];
    }
    return text;
}
