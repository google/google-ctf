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

#pragma once

#define CBC 0
#define CTR 0

#include "aes.h"

typedef uint8_t state_t[4][4];

void AES_AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey);

void AES_SubBytes(state_t* state);
void AES_ShiftRows(state_t* state);
void AES_MixColumns(state_t* state);

void AES_InvSubBytes(state_t* state);
void AES_InvShiftRows(state_t* state);
void AES_InvMixColumns(state_t* state);


int8_t AES_ECB_encrypt_step(const struct AES_ctx* ctx, uint8_t* buf, uint8_t step);
