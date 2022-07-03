#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import sys
from cffi import FFI
from pathlib import Path


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--pqclean_dir',
      type=str,
      default='/build/pqcrypto/third_party/PQClean',
      help='PQClean root dir')
  args = parser.parse_args()

  pqclean_dir = Path(args.pqclean_dir)
  common_dir = pqclean_dir / 'common'
  kyber_dir = pqclean_dir / 'crypto_kem/kyber512-90s/clean'
  assert (all([p.exists() for p in [pqclean_dir, common_dir, kyber_dir]]))

  ffi = FFI()
  ffi.cdef('''
typedef struct {
    int16_t coeffs[256];
} poly;

typedef struct {
    poly vec[2];
} polyvec;

extern const int16_t PQCLEAN_KYBER51290S_CLEAN_zetas[128];
void PQCLEAN_KYBER51290S_CLEAN_ntt(int16_t *r);
void PQCLEAN_KYBER51290S_CLEAN_invntt(int16_t *r);
void PQCLEAN_KYBER51290S_CLEAN_basemul(int16_t r[2], const int16_t a[2], const int16_t b[2], int16_t zeta);

void PQCLEAN_KYBER51290S_CLEAN_polyvec_compress(uint8_t *r, const polyvec *a);
void PQCLEAN_KYBER51290S_CLEAN_polyvec_decompress(polyvec *r, const uint8_t *a);
void PQCLEAN_KYBER51290S_CLEAN_polyvec_tobytes(uint8_t *r, const polyvec *a);
void PQCLEAN_KYBER51290S_CLEAN_polyvec_frombytes(polyvec *r, const uint8_t *a);
void PQCLEAN_KYBER51290S_CLEAN_polyvec_ntt(polyvec *r);
void PQCLEAN_KYBER51290S_CLEAN_polyvec_invntt_tomont(polyvec *r);
void PQCLEAN_KYBER51290S_CLEAN_polyvec_basemul_acc_montgomery(poly *r, const polyvec *a, const polyvec *b);
void PQCLEAN_KYBER51290S_CLEAN_polyvec_reduce(polyvec *r);
void PQCLEAN_KYBER51290S_CLEAN_polyvec_add(polyvec *r, const polyvec *a, const polyvec *b);

void PQCLEAN_KYBER51290S_CLEAN_poly_tobytes(uint8_t *r, const poly *a);
void PQCLEAN_KYBER51290S_CLEAN_poly_frombytes(poly *r, const uint8_t *a);
void PQCLEAN_KYBER51290S_CLEAN_poly_ntt(poly *r);
void PQCLEAN_KYBER51290S_CLEAN_poly_invntt_tomont(poly *r);
void PQCLEAN_KYBER51290S_CLEAN_poly_basemul_montgomery(poly *r, const poly *a, const poly *b);
void PQCLEAN_KYBER51290S_CLEAN_poly_tomont(poly *r);
void PQCLEAN_KYBER51290S_CLEAN_poly_reduce(poly *r);
void PQCLEAN_KYBER51290S_CLEAN_poly_add(poly *r, const poly *a, const poly *b);
void PQCLEAN_KYBER51290S_CLEAN_poly_sub(poly *r, const poly *a, const poly *b);

int16_t PQCLEAN_KYBER51290S_CLEAN_montgomery_reduce(int32_t a);
int16_t PQCLEAN_KYBER51290S_CLEAN_barrett_reduce(int16_t a);

void PQCLEAN_KYBER51290S_CLEAN_gen_matrix(polyvec *a, const uint8_t *seed, int transposed);
void PQCLEAN_KYBER51290S_CLEAN_indcpa_keypair(uint8_t *pk, uint8_t *sk);
void PQCLEAN_KYBER51290S_CLEAN_indcpa_enc(uint8_t *c, const uint8_t *m, const uint8_t *pk, const uint8_t *coins);
void PQCLEAN_KYBER51290S_CLEAN_indcpa_dec(uint8_t *m, const uint8_t *c, const uint8_t *sk);

int PQCLEAN_KYBER51290S_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_KYBER51290S_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_KYBER51290S_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#define KYBER_N ...
#define KYBER_Q ...
#define KYBER_K ...
#define KYBER_SSBYTES  ...
#define KYBER_POLYBYTES     ...
#define KYBER_POLYVECBYTES  ...

#define KYBER_PUBLICKEYBYTES  ...
#define KYBER_SECRETKEYBYTES  ...
#define KYBER_CIPHERTEXTBYTES ...

''')

  ffi.set_source(
      f"pqcrypto.kyber",
      f'''
        #include "ntt.h"
        #include "poly.h"
        #include "polyvec.h"
        #include "reduce.h"
        #include "indcpa.h"
        #include "kem.h"
      ''',
      sources=[
          str(kyber_dir / 'cbd.c'),
          str(kyber_dir / 'indcpa.c'),
          str(kyber_dir / 'kem.c'),
          str(kyber_dir / 'ntt.c'),
          str(kyber_dir / 'poly.c'),
          str(kyber_dir / 'polyvec.c'),
          str(kyber_dir / 'reduce.c'),
          str(kyber_dir / 'symmetric-aes.c'),
          str(kyber_dir / 'verify.c'),
          str(common_dir / 'aes.c'),
          str(common_dir / 'sha2.c'),
          str(common_dir / 'randombytes.c'),
      ],
      include_dirs=[str(common_dir), str(kyber_dir)],
      extra_compile_args=["-O3", "-std=c99"],
      extra_link_args=[],
      libraries=[],
  )

  ffi.compile(verbose=True)

  return 0


if __name__ == '__main__':
  sys.exit(main())
