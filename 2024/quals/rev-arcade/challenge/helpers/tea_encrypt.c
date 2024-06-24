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

#include <stdint.h>
#include <stdio.h>

void encrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */
    uint32_t delta=0xDEADBEEF;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        sum += delta;
        v0 += ((v1<<4) + k0) ^ (v1 + sum + 1) ^ ((v1>>5) + k1);
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
    }                                              /* end cycle */
    v[0]=v0; v[1]=v1;
}

void decrypt (uint32_t v[2], const uint32_t k[4]) {
    uint32_t v0=v[0], v1=v[1], sum=0xD5B7DDE0, i;  /* set up; sum is (delta << 5) & 0xFFFFFFFF */
    uint32_t delta=0xDEADBEEF;                     /* a key schedule constant */
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                  /* end cycle */
    v[0]=v0; v[1]=v1;
}

// Most of the comments in this file are outdated, trying to solve a former iteration of this challenge.
// I'll leave these here since it's still interesting to have around.
void main() {
    // This is the key.
    // LCTRL    - A
    // LALT     - B
    // SPACE    - C
    // LSHIFT   - D
    // Let's put a bogus key that we can change afterwards.
    // UP, UP, A+B, LEFT, LEFT+C, RIGHT+D, UP, DOWN
    // UP+A+B, DOWN+C+D, A+B+C, A+B+D, B+C, RIGHT, 
    // D, C, A+B+C+D
	//uint32_t key[4] = {0xf0408008, 0x60b0704230, 0x02018844, 0x20100101};
    // Easy key.
    // 0xdeadbeef 0xc5f2cccd 0x44f376df 0xf8461c48
    uint32_t key[4] = {0xdeadbeef, 0xc5f2cccd, 0x44f376df, 0xf8461c48};
    uint32_t zeros[4] = {0x00000000, 0x00000000, 0x00000000, 0x00000000};

    // This is the flag.
    // CTF{h@cK1ng_r3tR0_gAm32_F0r_fuN}
    // 80402010 b0051239 02a06608 7698f076 a4086615 30980408 20a47608 70890901
	uint32_t plaintext[] = {
        //CTF{
        0x80402010,
        //h@cK
        0xb0051239,
        //1ng_
        0x02a06608,
        //r3tR
        0x7698f076,
        //0_gA
        0xa4086615,
        //m32_
        0x30980408,
        //F0r_
        0x20a47608,
        //fuN}
        0x70890901
    };

	for (int i=0;i<8;i+=2) {
        encrypt(plaintext+i, key);
        printf("$%08x,", plaintext[i]);
	    printf("$%08x,", plaintext[i+1]);
	}
    printf("\n");
}
