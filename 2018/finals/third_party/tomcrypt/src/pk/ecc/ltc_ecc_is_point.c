/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/** Returns whether [x,y] is a point on curve defined by dp
  @param dp     curve parameters
  @param x      x point coordinate
  @param y      y point coordinate
  @return CRYPT_OK if valid
*/

int ltc_ecc_is_point(const ltc_ecc_dp *dp, void *x, void *y)
{
  void *prime, *a, *b, *t1, *t2;
  int err;

  prime = dp->prime;
  b     = dp->B;
  a     = dp->A;

  if ((err = mp_init_multi(&t1, &t2, NULL)) != CRYPT_OK)  return err;

  /* compute y^2 */
  if ((err = mp_sqr(y, t1)) != CRYPT_OK)                  goto cleanup;

  /* compute x^3 */
  if ((err = mp_sqr(x, t2)) != CRYPT_OK)                  goto cleanup;
  if ((err = mp_mod(t2, prime, t2)) != CRYPT_OK)          goto cleanup;
  if ((err = mp_mul(x, t2, t2)) != CRYPT_OK)              goto cleanup;

  /* compute y^2 - x^3 */
  if ((err = mp_sub(t1, t2, t1)) != CRYPT_OK)             goto cleanup;

  /* compute y^2 - x^3 - a*x */
  if ((err = mp_submod(prime, a, prime, t2)) != CRYPT_OK) goto cleanup;
  if ((err = mp_mulmod(t2, x, prime, t2)) != CRYPT_OK)    goto cleanup;
  if ((err = mp_addmod(t1, t2, prime, t1)) != CRYPT_OK)   goto cleanup;

  /* adjust range (0, prime) */
  while (mp_cmp_d(t1, 0) == LTC_MP_LT) {
     if ((err = mp_add(t1, prime, t1)) != CRYPT_OK)       goto cleanup;
  }
  while (mp_cmp(t1, prime) != LTC_MP_LT) {
     if ((err = mp_sub(t1, prime, t1)) != CRYPT_OK)       goto cleanup;
  }

  /* compare to b */
  if (mp_cmp(t1, b) != LTC_MP_EQ) {
     err = CRYPT_INVALID_PACKET;
  } else {
     err = CRYPT_OK;
  }

cleanup:
  mp_clear_multi(t1, t2, NULL);
  return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
