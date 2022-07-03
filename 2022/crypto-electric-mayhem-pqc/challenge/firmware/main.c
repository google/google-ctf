// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include <stdio.h>
#include <stdlib.h>

#include "api.h"
#include "elmoasmfunctionsdef.h"

#define PASTER(x, y) x##_##y
#define EVALUATOR(x, y) PASTER(x, y)
#define NAMESPACE(fun) EVALUATOR(PQCLEAN_KYBER51290S_CLEAN, fun)

#define CRYPTO_BYTES NAMESPACE(CRYPTO_BYTES)
#define CRYPTO_PUBLICKEYBYTES NAMESPACE(CRYPTO_PUBLICKEYBYTES)
#define CRYPTO_SECRETKEYBYTES NAMESPACE(CRYPTO_SECRETKEYBYTES)
#define CRYPTO_CIPHERTEXTBYTES NAMESPACE(CRYPTO_CIPHERTEXTBYTES)

#define crypto_kem_keypair NAMESPACE(crypto_kem_keypair)
#define crypto_kem_enc NAMESPACE(crypto_kem_enc)
#define crypto_kem_dec NAMESPACE(crypto_kem_dec)

static uint32_t N = 1;
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
static uint8_t ss[CRYPTO_BYTES];

int main() {
  // Read #traces.
  LoadN(&N);

  // Read private key.
  for (uint32_t j = 0; j < sizeof(sk); j++) {
    readbyte(&sk[j]);
  }

  for (uint32_t i = 0; i < N; i++) {
    // Read ciphertext.
    for (uint32_t j = 0; j < sizeof(ct); j++) {
      readbyte(&ct[j]);
    }

    // Analyze key decapsulation.
    // Internal polyvec_basemul_acc_montgomery() is patched with trigger calls.
    crypto_kem_dec(ss, ct, sk);

    // Write session key.
    for (uint32_t j = 0; j < sizeof(ss); j++) {
      printbyte(&ss[j]);
    }
  }

  endprogram();
  return 0;
}
