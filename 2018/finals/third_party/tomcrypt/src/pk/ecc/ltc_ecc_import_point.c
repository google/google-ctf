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

int ltc_ecc_import_point(const unsigned char *in, unsigned long inlen, void *prime, void *a, void *b, void *x, void *y)
{
   int err;
   unsigned long size;
   void *t1, *t2;

   /* init key + temporary numbers */
   if (mp_init_multi(&t1, &t2, NULL) != CRYPT_OK) {
      return CRYPT_MEM;
   }

   size = mp_unsigned_bin_size(prime);

   if (in[0] == 0x04 && (inlen&1) && ((inlen-1)>>1) == size) {
      /* read uncompressed point */
      /* load x */
      if ((err = mp_read_unsigned_bin(x, (unsigned char *)in+1, size)) != CRYPT_OK)      { goto cleanup; }
      /* load y */
      if ((err = mp_read_unsigned_bin(y, (unsigned char *)in+1+size, size)) != CRYPT_OK) { goto cleanup; }
   }
   else if ((in[0] == 0x02 || in[0] == 0x03) && (inlen-1) == size && ltc_mp.sqrtmod_prime != NULL) {
      /* read compressed point - BEWARE: requires sqrtmod_prime */
      /* load x */
      if ((err = mp_read_unsigned_bin(x, (unsigned char *)in+1, size)) != CRYPT_OK)      { goto cleanup; }
      /* compute x^3 */
      if ((err = mp_sqr(x, t1)) != CRYPT_OK)                                             { goto cleanup; }
      if ((err = mp_mulmod(t1, x, prime, t1)) != CRYPT_OK)                               { goto cleanup; }
      /* compute x^3 + a*x */
      if ((err = mp_mulmod(a, x, prime, t2)) != CRYPT_OK)                                { goto cleanup; }
      if ((err = mp_add(t1, t2, t1)) != CRYPT_OK)                                        { goto cleanup; }
      /* compute x^3 + a*x + b */
      if ((err = mp_add(t1, b, t1)) != CRYPT_OK)                                         { goto cleanup; }
      /* compute sqrt(x^3 + a*x + b) */
      if ((err = mp_sqrtmod_prime(t1, prime, t2)) != CRYPT_OK)                           { goto cleanup; }
      /* adjust y */
      if ((mp_isodd(t2) && in[0] == 0x03) || (!mp_isodd(t2) && in[0] == 0x02)) {
         if ((err = mp_mod(t2, prime, y)) != CRYPT_OK)                                   { goto cleanup; }
      }
      else {
         if ((err = mp_submod(prime, t2, prime, y)) != CRYPT_OK)                         { goto cleanup; }
      }
   }
   else {
      err = CRYPT_INVALID_PACKET;
      goto cleanup;
   }

   err = CRYPT_OK;
cleanup:
   mp_clear_multi(t1, t2, NULL);
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
