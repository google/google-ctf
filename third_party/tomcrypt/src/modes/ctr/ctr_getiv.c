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
   @file ctr_getiv.c
   CTR implementation, get IV, Tom St Denis
*/

#ifdef LTC_CTR_MODE

/**
   Get the current initialization vector
   @param IV   [out] The destination of the initialization vector
   @param len  [in/out]  The max size and resulting size of the initialization vector
   @param ctr  The CTR state
   @return CRYPT_OK if successful
*/
int ctr_getiv(unsigned char *IV, unsigned long *len, const symmetric_CTR *ctr)
{
   LTC_ARGCHK(IV  != NULL);
   LTC_ARGCHK(len != NULL);
   LTC_ARGCHK(ctr != NULL);
   if ((unsigned long)ctr->blocklen > *len) {
      *len = ctr->blocklen;
      return CRYPT_BUFFER_OVERFLOW;
   }
   XMEMCPY(IV, ctr->ctr, ctr->blocklen);
   *len = ctr->blocklen;

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
