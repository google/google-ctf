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
  @file ltc_ecc_mulmod_timing.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

#ifdef LTC_ECC_TIMING_RESISTANT

/**
   Perform a point multiplication  (timing resistant)
   @param k    The scalar to multiply by
   @param G    The base point
   @param R    [out] Destination for kG
   @param a    ECC curve parameter a
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1==map, 0 == leave in projective)
   @return CRYPT_OK on success
*/
int ltc_ecc_mulmod(void *k, const ecc_point *G, ecc_point *R, void *a, void *modulus, int map)
{
   ecc_point *tG, *M[3];
   int        i, j, err, inf;
   void       *mp = NULL, *mu = NULL, *ma = NULL, *a_plus3 = NULL;
   ltc_mp_digit buf;
   int        bitcnt, mode, digidx;

   LTC_ARGCHK(k       != NULL);
   LTC_ARGCHK(G       != NULL);
   LTC_ARGCHK(R       != NULL);
   LTC_ARGCHK(modulus != NULL);

   if ((err = ltc_ecc_is_point_at_infinity(G, modulus, &inf)) != CRYPT_OK) return err;
   if (inf) {
      /* return the point at infinity */
      return ltc_ecc_set_point_xyz(1, 1, 0, R);
   }

   /* init montgomery reduction */
   if ((err = mp_montgomery_setup(modulus, &mp)) != CRYPT_OK)        { goto error; }
   if ((err = mp_init(&mu)) != CRYPT_OK)                             { goto error; }
   if ((err = mp_montgomery_normalization(mu, modulus)) != CRYPT_OK) { goto error; }

   /* for curves with a == -3 keep ma == NULL */
   if ((err = mp_init(&a_plus3)) != CRYPT_OK)                        { goto error; }
   if ((err = mp_add_d(a, 3, a_plus3)) != CRYPT_OK)                  { goto error; }
   if (mp_cmp(a_plus3, modulus) != LTC_MP_EQ) {
      if ((err = mp_init(&ma)) != CRYPT_OK)                          { goto error; }
      if ((err = mp_mulmod(a, mu, modulus, ma)) != CRYPT_OK)         { goto error; }
   }

   /* alloc ram for window temps */
   for (i = 0; i < 3; i++) {
      M[i] = ltc_ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ltc_ecc_del_point(M[j]);
         }
         mp_clear(mu);
         mp_montgomery_free(mp);
         return CRYPT_MEM;
      }
   }

   /* make a copy of G incase R==G */
   tG = ltc_ecc_new_point();
   if (tG == NULL)                                                                   { err = CRYPT_MEM; goto done; }

   /* tG = G  and convert to montgomery */
   if ((err = mp_mulmod(G->x, mu, modulus, tG->x)) != CRYPT_OK)                      { goto done; }
   if ((err = mp_mulmod(G->y, mu, modulus, tG->y)) != CRYPT_OK)                      { goto done; }
   if ((err = mp_mulmod(G->z, mu, modulus, tG->z)) != CRYPT_OK)                      { goto done; }
   mp_clear(mu);
   mu = NULL;

   /* calc the M tab */
   /* M[0] == G */
   if ((err = ltc_ecc_copy_point(tG, M[0])) != CRYPT_OK)                             { goto done; }
   /* M[1] == 2G */
   if ((err = ltc_mp.ecc_ptdbl(tG, M[1], ma, modulus, mp)) != CRYPT_OK)              { goto done; }

   /* setup sliding window */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = mp_get_digit_count(k) - 1;

   /* perform ops */
   for (;;) {
     /* grab next digit as required */
      if (--bitcnt == 0) {
         if (digidx == -1) {
            break;
         }
         buf    = mp_get_digit(k, digidx);
         bitcnt = (int) MP_DIGIT_BIT;
         --digidx;
      }

      /* grab the next msb from the ltiplicand */
      i = (int)((buf >> (MP_DIGIT_BIT - 1)) & 1);
      buf <<= 1;

      if (mode == 0 && i == 0) {
         /* dummy operations */
         if ((err = ltc_mp.ecc_ptadd(M[0], M[1], M[2], ma, modulus, mp)) != CRYPT_OK) { goto done; }
         if ((err = ltc_mp.ecc_ptdbl(M[1], M[2], ma, modulus, mp)) != CRYPT_OK)       { goto done; }
         continue;
      }

      if (mode == 0 && i == 1) {
         mode = 1;
         /* dummy operations */
         if ((err = ltc_mp.ecc_ptadd(M[0], M[1], M[2], ma, modulus, mp)) != CRYPT_OK) { goto done; }
         if ((err = ltc_mp.ecc_ptdbl(M[1], M[2], ma, modulus, mp)) != CRYPT_OK)       { goto done; }
         continue;
      }

      if ((err = ltc_mp.ecc_ptadd(M[0], M[1], M[i^1], ma, modulus, mp)) != CRYPT_OK)  { goto done; }
      if ((err = ltc_mp.ecc_ptdbl(M[i], M[i], ma, modulus, mp)) != CRYPT_OK)          { goto done; }
   }

   /* copy result out */
   if ((err = ltc_ecc_copy_point(M[0], R)) != CRYPT_OK)                              { goto done; }

   /* map R back from projective space */
   if (map) {
      err = ltc_ecc_map(R, modulus, mp);
   } else {
      err = CRYPT_OK;
   }
done:
   ltc_ecc_del_point(tG);
   for (i = 0; i < 3; i++) {
       ltc_ecc_del_point(M[i]);
   }
error:
   if (ma != NULL) mp_clear(ma);
   if (a_plus3 != NULL) mp_clear(a_plus3);
   if (mu != NULL) mp_clear(mu);
   if (mp != NULL) mp_montgomery_free(mp);
   return err;
}

#endif
#endif
/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */

