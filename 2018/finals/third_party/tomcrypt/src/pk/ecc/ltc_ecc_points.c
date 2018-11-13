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
  @file ltc_ecc_points.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
   Allocate a new ECC point
   @return A newly allocated point or NULL on error
*/
ecc_point *ltc_ecc_new_point(void)
{
   ecc_point *p;
   p = XCALLOC(1, sizeof(*p));
   if (p == NULL) {
      return NULL;
   }
   if (mp_init_multi(&p->x, &p->y, &p->z, NULL) != CRYPT_OK) {
      XFREE(p);
      return NULL;
   }
   return p;
}

/** Free an ECC point from memory
  @param p   The point to free
*/
void ltc_ecc_del_point(ecc_point *p)
{
   /* prevents free'ing null arguments */
   if (p != NULL) {
      mp_clear_multi(p->x, p->y, p->z, NULL); /* note: p->z may be NULL but that's ok with this function anyways */
      XFREE(p);
   }
}

int ltc_ecc_set_point_xyz(ltc_mp_digit x, ltc_mp_digit y, ltc_mp_digit z, ecc_point *p)
{
   int err;
   if ((err = ltc_mp.set_int(p->x, x)) != CRYPT_OK) return err;
   if ((err = ltc_mp.set_int(p->y, y)) != CRYPT_OK) return err;
   if ((err = ltc_mp.set_int(p->z, z)) != CRYPT_OK) return err;
   return CRYPT_OK;
}

int ltc_ecc_copy_point(const ecc_point *src, ecc_point *dst)
{
   int err;
   if ((err = ltc_mp.copy(src->x, dst->x)) != CRYPT_OK) return err;
   if ((err = ltc_mp.copy(src->y, dst->y)) != CRYPT_OK) return err;
   if ((err = ltc_mp.copy(src->z, dst->z)) != CRYPT_OK) return err;
   return CRYPT_OK;
}

#endif
/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */

