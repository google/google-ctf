/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

/* origin of this code - OLPC */

#ifdef LTC_MECC

/**
  Verify a key according to ANSI spec
  @param key     The key to validate
  @return CRYPT_OK if successful
*/

int ltc_ecc_verify_key(const ecc_key *key)
{
   int err, inf;
   ecc_point *point;
   void *prime = key->dp.prime;
   void *order = key->dp.order;
   void *a     = key->dp.A;

   /* Test 1: Are the x and y points of the public key in the field? */
   if (ltc_mp.compare_d(key->pubkey.z, 1) == LTC_MP_EQ) {
      if ((ltc_mp.compare(key->pubkey.x, prime) != LTC_MP_LT) ||
          (ltc_mp.compare(key->pubkey.y, prime) != LTC_MP_LT) ||
          (ltc_mp.compare_d(key->pubkey.x, 0) == LTC_MP_LT) ||
          (ltc_mp.compare_d(key->pubkey.y, 0) == LTC_MP_LT) ||
          (mp_iszero(key->pubkey.x) && mp_iszero(key->pubkey.y))
         )
      {
         err = CRYPT_INVALID_PACKET;
         goto done2;
      }
   }

   /* Test 2: is the public key on the curve? */
   if ((err = ltc_ecc_is_point(&key->dp, key->pubkey.x, key->pubkey.y)) != CRYPT_OK)      { goto done2; }

   /* Test 3: does nG = O? (n = order, O = point at infinity, G = public key) */
   point = ltc_ecc_new_point();
   if ((err = ltc_ecc_mulmod(order, &(key->pubkey), point, a, prime, 1)) != CRYPT_OK)     { goto done1; }

   err = ltc_ecc_is_point_at_infinity(point, prime, &inf);
   if (err != CRYPT_OK || inf) {
      err = CRYPT_ERROR;
   }
   else {
      err = CRYPT_OK;
   }

done1:
   ltc_ecc_del_point(point);
done2:
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
