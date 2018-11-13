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

/* http://crypto.stackexchange.com/questions/41468/point-at-infinity-for-jacobian-coordinates
 * a point at infinity is any point (x,y,0) such that y^2 == x^3, except (0,0,0)
 */

int ltc_ecc_is_point_at_infinity(const ecc_point *P, void *modulus, int *retval)
{
   int err;
   void  *x3, *y2;

   /* trivial case */
   if (!mp_iszero(P->z)) {
      *retval = 0;
      return CRYPT_OK;
   }

   /* point (0,0,0) is not at infinity */
   if (mp_iszero(P->x) && mp_iszero(P->y)) {
      *retval = 0;
      return CRYPT_OK;
   }

   /* initialize */
   if ((err = mp_init_multi(&x3, &y2, NULL))      != CRYPT_OK)   goto done;

   /* compute y^2 */
   if ((err = mp_mulmod(P->y, P->y, modulus, y2)) != CRYPT_OK)   goto cleanup;

   /* compute x^3 */
   if ((err = mp_mulmod(P->x, P->x, modulus, x3)) != CRYPT_OK)   goto cleanup;
   if ((err = mp_mulmod(P->x, x3, modulus, x3))   != CRYPT_OK)   goto cleanup;

   /* test y^2 == x^3 */
   err = CRYPT_OK;
   if ((mp_cmp(x3, y2) == LTC_MP_EQ) && !mp_iszero(y2)) {
      *retval = 1;
   } else {
      *retval = 0;
   }

cleanup:
   mp_clear_multi(x3, y2, NULL);
done:
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
