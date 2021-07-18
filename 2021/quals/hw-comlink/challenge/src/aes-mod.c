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

#include "aes-mod.h"

/*
// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey)
{
  uint8_t round = 0;

  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);

  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr rounds are executed in the loop below.
  // Last one without MixColumns()
  for (round = 1; ; ++round)
  {
    SubBytes(state);
    ShiftRows(state);
    if (round == Nr) {
      break;
    }
    MixColumns(state);
    AddRoundKey(round, state, RoundKey);
  }
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey);
}
*/

int8_t AES_Cipher_step(state_t* state, const uint8_t* RoundKey, uint8_t step) {
    if(step == 1) {
        AES_AddRoundKey(step-1, state, RoundKey);
        return 0;
    } else if(step >= 2 && step < 11) {
        AES_SubBytes(state);
        AES_ShiftRows(state);
        AES_MixColumns(state);
        AES_AddRoundKey(step-1, state, RoundKey);
        return 0;
    } else if(step == 11) {
        AES_SubBytes(state);
        AES_ShiftRows(state);
        AES_AddRoundKey(step-1, state, RoundKey);
        return 1;
    } else {
        return -1;
    }
}

int8_t AES_ECB_encrypt_step(const struct AES_ctx* ctx, uint8_t* buf, uint8_t step) {
    return AES_Cipher_step((state_t*)buf, ctx->RoundKey, step);
}
