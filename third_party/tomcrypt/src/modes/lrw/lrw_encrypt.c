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
   @file lrw_encrypt.c
   LRW_MODE implementation, Encrypt blocks, Tom St Denis
*/

#ifdef LTC_LRW_MODE

/**
  LRW encrypt blocks
  @param pt     The plaintext
  @param ct     [out] The ciphertext
  @param len    The length in octets, must be a multiple of 16
  @param lrw    The LRW state
*/
int lrw_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long len, symmetric_LRW *lrw)
{
   int err;

   LTC_ARGCHK(pt  != NULL);
   LTC_ARGCHK(ct  != NULL);
   LTC_ARGCHK(lrw != NULL);

   if ((err = cipher_is_valid(lrw->cipher)) != CRYPT_OK) {
      return err;
   }

   if (cipher_descriptor[lrw->cipher].accel_lrw_encrypt != NULL) {
      return cipher_descriptor[lrw->cipher].accel_lrw_encrypt(pt, ct, len, lrw->IV, lrw->tweak, &lrw->key);
   }

   return lrw_process(pt, ct, len, LRW_ENCRYPT, lrw);
}


#endif
/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
