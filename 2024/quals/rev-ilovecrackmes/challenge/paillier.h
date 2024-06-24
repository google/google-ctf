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

#ifndef PAILLIER_H
#define PAILLIER_H

#include <memory>
#include <optional>
#include <string>

#include <openssl/bn.h>


#define VAR(var)                                \
  BIGNUM* var = BN_secure_new();                \
  if (var == nullptr) { return false; }

#define MAKE_PRIME(var, nbits, ctx)                                     \
  if (BN_generate_prime_ex2(var, nbits, 0, nullptr, nullptr, nullptr, ctx) == 0) { \
    return false;                                                       \
  }                                                                     \

#define CHECK_OP(expr) if (expr == 0 ) { return false; }


#ifdef DEBUG
#define PRINT_VAR(var) \
  std::cout << #var " = " << std::string(BN_bn2dec(var)) << '\n'
#else
#define PRINT_VAR(var)
#endif

class Paillier {
public:

  bool Init(int nbits);
  bool Encrypt(BIGNUM* result, BIGNUM* m);
  bool Decrypt(BIGNUM* result, BIGNUM* c);

  BIGNUM* g_;
  BN_CTX* ctx_;

private:
  bool Lcm(BIGNUM* result, BIGNUM* a, BIGNUM* b);
  bool L(BIGNUM* result, BIGNUM* x);
  bool MulInv(BIGNUM* result, BIGNUM* a, BIGNUM* m);
  bool FindCoprime(BIGNUM* result);


  BIGNUM* n_;
  BIGNUM* nsquared_;
  BIGNUM* lambda_;
  BIGNUM* mu_;
  BIGNUM* zero_;
  BIGNUM* one_;
};

#endif
