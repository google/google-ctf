/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_RNG_MAKE_PRNG
/**
  @file rng_make_prng.c
  portable way to get secure random bits to feed a PRNG  (Tom St Denis)
*/

/**
  Create a PRNG from a RNG

     In case you pass bits as '-1' the PRNG will be setup
     as if the export/import functionality has been used,
     but the imported data comes directly from the RNG.

  @param bits     Number of bits of entropy desired (-1 or 64 ... 1024)
  @param wprng    Index of which PRNG to setup
  @param prng     [out] PRNG state to initialize
  @param callback A pointer to a void function for when the RNG is slow, this can be NULL
  @return CRYPT_OK if successful
*/
int rng_make_prng(int bits, int wprng, prng_state *prng,
                  void (*callback)(void))
{
   unsigned char* buf;
   unsigned long bytes;
   int err;

   LTC_ARGCHK(prng != NULL);

   /* check parameter */
   if ((err = prng_is_valid(wprng)) != CRYPT_OK) {
      return err;
   }

   if (bits == -1) {
      bytes = prng_descriptor[wprng].export_size;
   } else if (bits < 64 || bits > 1024) {
      return CRYPT_INVALID_PRNGSIZE;
   } else {
      bytes = (unsigned long)((bits+7)/8) * 2;
   }

   if ((err = prng_descriptor[wprng].start(prng)) != CRYPT_OK) {
      return err;
   }

   buf = XMALLOC(bytes);
   if (buf == NULL) {
      return CRYPT_MEM;
   }

   if (rng_get_bytes(buf, bytes, callback) != bytes) {
      err = CRYPT_ERROR_READPRNG;
      goto LBL_ERR;
   }

   if (bits == -1) {
      if ((err = prng_descriptor[wprng].pimport(buf, bytes, prng)) != CRYPT_OK) {
         goto LBL_ERR;
      }
   } else {
      if ((err = prng_descriptor[wprng].add_entropy(buf, bytes, prng)) != CRYPT_OK) {
         goto LBL_ERR;
      }
   }
   if ((err = prng_descriptor[wprng].ready(prng)) != CRYPT_OK) {
      goto LBL_ERR;
   }

LBL_ERR:
   #ifdef LTC_CLEAN_STACK
   zeromem(buf, bytes);
   #endif
   XFREE(buf);
   return err;
}
#endif /* #ifdef LTC_RNG_MAKE_PRNG */


/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
