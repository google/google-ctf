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
  @file ltc_ecc_mulmod.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC
#ifndef LTC_ECC_TIMING_RESISTANT

/* size of sliding window, don't change this! */
#define WINSIZE 4

/**
   Perform a point multiplication
   @param k    The scalar to multiply by
   @param G    The base point
   @param R    [out] Destination for kG
   @param modulus  The modulus of the field the ECC curve is in
   @param map      Boolean whether to map back to affine or not (1==map, 0 == leave in projective)
   @return CRYPT_OK on success
*/
int ltc_ecc_mulmod(void *k, const ecc_point *G, ecc_point *R, void *a, void *modulus, int map)
{
   ecc_point *tG, *M[8];
   int        i, j, err, inf;
   void       *mp = NULL, *mu = NULL, *ma = NULL, *a_plus3 = NULL;
   ltc_mp_digit buf;
   int        first, bitbuf, bitcpy, bitcnt, mode, digidx;

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
  for (i = 0; i < 8; i++) {
      M[i] = ltc_ecc_new_point();
      if (M[i] == NULL) {
         for (j = 0; j < i; j++) {
             ltc_ecc_del_point(M[j]);
         }
         err = CRYPT_MEM;
         goto error;
      }
  }

   /* make a copy of G incase R==G */
   tG = ltc_ecc_new_point();
   if (tG == NULL)                                                                   { err = CRYPT_MEM; goto done; }

   /* tG = G  and convert to montgomery */
   if (mp_cmp_d(mu, 1) == LTC_MP_EQ) {
      if ((err = ltc_ecc_copy_point(G, tG)) != CRYPT_OK)                             { goto done; }
   } else {
      if ((err = mp_mulmod(G->x, mu, modulus, tG->x)) != CRYPT_OK)                   { goto done; }
      if ((err = mp_mulmod(G->y, mu, modulus, tG->y)) != CRYPT_OK)                   { goto done; }
      if ((err = mp_mulmod(G->z, mu, modulus, tG->z)) != CRYPT_OK)                   { goto done; }
   }
   mp_clear(mu);
   mu = NULL;

   /* calc the M tab, which holds kG for k==8..15 */
   /* M[0] == 8G */
   if ((err = ltc_mp.ecc_ptdbl(tG, M[0], ma, modulus, mp)) != CRYPT_OK)              { goto done; }
   if ((err = ltc_mp.ecc_ptdbl(M[0], M[0], ma, modulus, mp)) != CRYPT_OK)            { goto done; }
   if ((err = ltc_mp.ecc_ptdbl(M[0], M[0], ma, modulus, mp)) != CRYPT_OK)            { goto done; }

   /* now find (8+k)G for k=1..7 */
   for (j = 9; j < 16; j++) {
       if ((err = ltc_mp.ecc_ptadd(M[j-9], tG, M[j-8], ma, modulus, mp)) != CRYPT_OK) { goto done; }
   }

   /* setup sliding window */
   mode   = 0;
   bitcnt = 1;
   buf    = 0;
   digidx = mp_get_digit_count(k) - 1;
   bitcpy = bitbuf = 0;
   first  = 1;

   /* perform ops */
   for (;;) {
     /* grab next digit as required */
     if (--bitcnt == 0) {
       if (digidx == -1) {
          break;
       }
       buf    = mp_get_digit(k, digidx);
       bitcnt = (int) ltc_mp.bits_per_digit;
       --digidx;
     }

     /* grab the next msb from the ltiplicand */
     i = (buf >> (ltc_mp.bits_per_digit - 1)) & 1;
     buf <<= 1;

     /* skip leading zero bits */
     if (mode == 0 && i == 0) {
        continue;
     }

     /* if the bit is zero and mode == 1 then we double */
     if (mode == 1 && i == 0) {
        if ((err = ltc_mp.ecc_ptdbl(R, R, ma, modulus, mp)) != CRYPT_OK)             { goto done; }
        continue;
     }

     /* else we add it to the window */
     bitbuf |= (i << (WINSIZE - ++bitcpy));
     mode = 2;

     if (bitcpy == WINSIZE) {
       /* if this is the first window we do a simple copy */
       if (first == 1) {
          /* R = kG [k = first window] */
          if ((err = ltc_ecc_copy_point(M[bitbuf-8], R)) != CRYPT_OK)                { goto done; }
          first = 0;
       } else {
         /* normal window */
         /* ok window is filled so double as required and add  */
         /* double first */
         for (j = 0; j < WINSIZE; j++) {
           if ((err = ltc_mp.ecc_ptdbl(R, R, ma, modulus, mp)) != CRYPT_OK)          { goto done; }
         }

         /* then add, bitbuf will be 8..15 [8..2^WINSIZE] guaranteed */
         if ((err = ltc_mp.ecc_ptadd(R, M[bitbuf-8], R, ma, modulus, mp)) != CRYPT_OK) { goto done; }
       }
       /* empty window and reset */
       bitcpy = bitbuf = 0;
       mode = 1;
    }
  }

   /* if bits remain then double/add */
   if (mode == 2 && bitcpy > 0) {
     /* double then add */
     for (j = 0; j < bitcpy; j++) {
       /* only double if we have had at least one add first */
       if (first == 0) {
          if ((err = ltc_mp.ecc_ptdbl(R, R, ma, modulus, mp)) != CRYPT_OK)           { goto done; }
       }

       bitbuf <<= 1;
       if ((bitbuf & (1 << WINSIZE)) != 0) {
         if (first == 1){
            /* first add, so copy */
            if ((err = ltc_ecc_copy_point(tG, R)) != CRYPT_OK)                      { goto done; }
            first = 0;
         } else {
            /* then add */
            if ((err = ltc_mp.ecc_ptadd(R, tG, R, ma, modulus, mp)) != CRYPT_OK)     { goto done; }
         }
       }
     }
   }

   /* map R back from projective space */
   if (map) {
      err = ltc_ecc_map(R, modulus, mp);
   } else {
      err = CRYPT_OK;
   }
done:
   ltc_ecc_del_point(tG);
   for (i = 0; i < 8; i++) {
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

#undef WINSIZE

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
