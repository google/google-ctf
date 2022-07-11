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

extern "C" {
#include "api.h"
}

#undef NDEBUG
#include <assert.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

void JsonWrite(const char *key, const uint8_t *buf, const int len, FILE *f,
               bool more = true) {
  char temp[128];
  int l = snprintf(temp, sizeof(temp), "\"%s\": [", key);
  fwrite(temp, 1, l, f);
  for (int i = 0; i < len; i++) {
    l = snprintf(temp, sizeof(temp), "%d%s", buf[i], (i == len - 1 ? "" : ","));
    fwrite(temp, 1, l, f);
  }
  l = snprintf(temp, sizeof(temp), "]%s\n", (more ? "," : ""));
  fwrite(temp, 1, l, f);
}

int main(int argc, char *argv[]) {
  // keygen [flag] [#messages] [output]
  assert(argc == 4);
  uint8_t flag[CRYPTO_BYTES] = {};
  {
    FILE *f = fopen(argv[1], "r");
    size_t read = fread(flag, 1, sizeof(flag), f);
    assert(read == sizeof(flag));
    fclose(f);
  }

  int n = atoi(argv[2]);
  assert(n > 0);

  FILE *output = fopen(argv[3], "w");
  fwrite("{", 1, 1, output);

  uint8_t pk[CRYPTO_PUBLICKEYBYTES] = {};
  uint8_t sk[CRYPTO_SECRETKEYBYTES] = {};

  printf("Generating Kyber key-pair\n");
  int rc = crypto_kem_keypair(pk, sk);
  assert(rc == 0);

  JsonWrite("pk", pk, sizeof(pk), output);
  JsonWrite("sk", sk, sizeof(sk), output);

  printf("Generating %d shared secrets\n", n);
  fwrite("\"sessions\":[\"", 1, 12, output);
  for (int i = 0; i < n; i++) {
    // Generate session key.
    uint8_t ct[CRYPTO_CIPHERTEXTBYTES] = {};
    uint8_t ss[CRYPTO_BYTES] = {};
    rc = crypto_kem_enc(ct, ss, pk);
    assert(rc == 0);

    // Sanity check.
    uint8_t recovered_ss[CRYPTO_BYTES] = {};
    rc = crypto_kem_dec(recovered_ss, ct, sk);
    assert(rc == 0);
    rc = memcmp(ss, recovered_ss, sizeof(ss));
    assert(rc == 0);

    // Encrypt flag under session key (one time pad).
    uint8_t enc_flag[CRYPTO_BYTES];
    for (int j = 0; j < sizeof(ss); j++) {
      enc_flag[j] = flag[j] ^ ss[j];
    }

    // Json output.
    char footer[16];
    fwrite("{", 1, 1, output);
    JsonWrite("ct", ct, sizeof(ct), output);
    JsonWrite("flag_xor_ss", enc_flag, sizeof(enc_flag), output,
              /*more=*/false);
    int l = snprintf(footer, sizeof(footer), "}%s\n", (i < n - 1 ? "," : ""));
    fwrite(footer, 1, l, output);
  }

  fwrite("]}", 1, 2, output);
  fclose(output);
  return 0;
}
