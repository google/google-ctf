/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <emmintrin.h>
#include <smmintrin.h>

const char* EXPECTED_PREFIX = "CTF{";

// This is cyclic, forming a chain of length 16.
uint8_t SHUFFLE[16] = {
    2, 6, 7, 1, 5, 11, 9, 14, 3, 15, 4, 8, 10, 12, 13, 0,
};
uint32_t ADD32[4] = {
    0xdeadbeef, 0xfee1dead, 0x13371337, 0x67637466,
};
uint8_t XOR[16] = {
    0x76, 0x58, 0xB4, 0x49, 0x8D, 0x1A, 0x5F, 0x38, 0xD4, 0x23, 0xF8, 0x34, 0xEB, 0x86, 0xF9, 0xAA,
};

#define PX(p) (*((__m128i*) p))
#define XS(x) ((char*) &x)

int main(void) {
    __m128i input, data;
    printf("Flag: ");
    scanf("%15s", XS(input));

    data = input;
    data = _mm_shuffle_epi8(data, PX(SHUFFLE));
    data = _mm_add_epi32(data, PX(ADD32));
    data = _mm_xor_si128(data, PX(XOR));

    if (strncmp(XS(input), XS(data), 16) == 0 && strncmp(XS(data), EXPECTED_PREFIX, 4) == 0) {
        printf("SUCCESS\n");
        return 0;
    } else {
        printf("FAILURE\n");
        return 1;
    }
}
