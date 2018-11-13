/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

/**
  @file ecc_sizes.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

void ecc_sizes(int *low, int *high)
{
  int i, size;
  void *prime;

  LTC_ARGCHKVD(low  != NULL);
  LTC_ARGCHKVD(high != NULL);

  *low = INT_MAX;
  *high = 0;

  if (mp_init(&prime) == CRYPT_OK) {
    for (i = 0; ltc_ecc_curves[i].prime != NULL; i++) {
       if (mp_read_radix(prime, ltc_ecc_curves[i].prime, 16) == CRYPT_OK) {
         size = mp_unsigned_bin_size(prime);
         if (size < *low)  *low  = size;
         if (size > *high) *high = size;
       }
    }
    mp_clear(prime);
  }
}

#endif
/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */

