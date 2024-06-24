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

#include <utility>

#include "rc4.h"

RC4State RC4Init(uint8_t *key, size_t keylen) {

    int j = 0;

    RC4State rc4;
    for(int i = 0; i < std::size(rc4); i++) {
        rc4[i] = i;
    }

    for(int i = 0; i < std::size(rc4); i++) {
        j = (j + rc4[i] + key[i % keylen]) % std::size(rc4);

        std::swap(rc4[i], rc4[j]);
    }

    return rc4;
}

void RC4Crypt(RC4State& rc4, uint8_t *in, uint8_t *out, size_t len) {

    int i = 0;
    int j = 0;

    for(size_t n = 0; n < len; n++) {
        i = (i + 1) % std::size(rc4);
        j = (j + rc4[i]) % std::size(rc4);

        std::swap(rc4[i], rc4[j]);
        int rnd = rc4[(rc4[i] + rc4[j]) % std::size(rc4)];

        out[n] = rnd ^ in[n];

    }
}

