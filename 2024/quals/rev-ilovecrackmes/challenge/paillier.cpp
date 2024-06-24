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

#include "paillier.h"

#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include <openssl/bn.h>


bool Paillier::Init(int nbits) {

  ctx_ = BN_CTX_new();
  if (ctx_ == nullptr) {
    return false;
  }

  VAR(zero);
  BN_zero(zero); // this is void function
  zero_ = zero;

  VAR(one);
  CHECK_OP(BN_one(one));
  one_ = one;


  VAR(p);
  MAKE_PRIME(p, nbits, ctx_);
  PRINT_VAR(p);

  VAR(q);
  CHECK_OP(BN_copy(q, p));

  while (BN_cmp(p, q) == 0) {
    MAKE_PRIME(q, nbits, ctx_);
  };

  PRINT_VAR(q);

  VAR(n);
  CHECK_OP(BN_mul(n, p, q, ctx_));
  PRINT_VAR(n);
  n_ = n;

  VAR(nsquared);
  CHECK_OP(BN_sqr(nsquared, n, ctx_));
  PRINT_VAR(nsquared);
  nsquared_ = nsquared;

  VAR(pminusone);
  VAR(qminusone);

  CHECK_OP(BN_sub(pminusone, p, one_));
  CHECK_OP(BN_sub(qminusone, q, one_));

  VAR(lambda);
  if (!Lcm(lambda, pminusone, qminusone)) {
    return false;
  }
  PRINT_VAR(lambda);
  lambda_ = lambda;

  VAR(g);
  CHECK_OP(BN_add(g, n, one_));
  PRINT_VAR(g);
  g_ = g;

  // Computing mu
  VAR(tmp1); // (g^lambda) % nsquared
  CHECK_OP(BN_mod_exp(tmp1, g, lambda, nsquared, ctx_));
  VAR(tmp2); // L(tmp1) = L((g^lambda) % nsquared)
  if (!L(tmp2, tmp1)) { return false; }

  VAR(mu);
  CHECK_OP(BN_mod_inverse(mu, tmp2, n_, ctx_));
  PRINT_VAR(mu);
  mu_ = mu;
  // Mu computed

  return true;
}


bool Paillier::Lcm(BIGNUM* result, BIGNUM* a, BIGNUM* b) {
  // lcm (a, b) = (a * b) / gcd(a, b)
  CHECK_OP(BN_mul(result, a, b, ctx_)); // result = a * b
  VAR(gcd);
  CHECK_OP(BN_gcd(gcd, a, b, ctx_));
  CHECK_OP(BN_div(result, NULL, result, gcd, ctx_));
  return true;
}


bool Paillier::L(BIGNUM* result, BIGNUM* x) {
  // (x - 1) // n
  CHECK_OP(BN_sub(result, x, BN_value_one()));
  CHECK_OP(BN_div(result, NULL, result, n_, ctx_));
  return true;
}


bool Paillier::FindCoprime(BIGNUM* result) {

  VAR(gcd);

  for(;;) {
    // 0 <= result < n_
    CHECK_OP(BN_rand_range(result, n_));

    // We don't want 0
    if (BN_cmp(result, zero_) <= 0) {
      continue;
    }

    // If we can't compute GCD, error out
    CHECK_OP(BN_gcd(gcd, result, n_, ctx_));

    // If gcd is 1 then these are comprimes
    if (BN_cmp(gcd, one_) == 0) {
      break;
    }
  }

  return true;
}


bool Paillier::Encrypt(BIGNUM* result, BIGNUM* m) {
  if (BN_cmp(m, zero_) <= 0 || BN_cmp(m, n_) >= 0) {
    return false;
  }
  VAR(r);
  if (!FindCoprime(r)) {
    return false;
  }
  // PRINT_VAR(r);

  VAR(tmp1); // (g ^ m) % nsquared
  CHECK_OP(BN_mod_exp(tmp1, g_, m, nsquared_, ctx_));
  // PRINT_VAR(tmp1);

  VAR(tmp2); // (r ^ n) % nsquared
  CHECK_OP(BN_mod_exp(tmp2, r, n_, nsquared_, ctx_));
  // PRINT_VAR(tmp2);

  CHECK_OP(BN_mod_mul(result, tmp1, tmp2, nsquared_, ctx_));
  return true;
}


bool Paillier::Decrypt(BIGNUM* result, BIGNUM* c) {
  VAR(tmp1); // (c ^ lambda) % nsquared
  CHECK_OP(BN_mod_exp(tmp1, c, lambda_, nsquared_, ctx_));

  VAR(tmp2);
  CHECK_OP(BN_mul(tmp2, tmp1, mu_, ctx_));

  if (!L(result, tmp2)) { return false; }
  CHECK_OP(BN_mod(result, result, n_, ctx_));
  return true;
}
