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
   @file lrw_getiv.c
   LRW_MODE implementation, Retrieve the current IV, Tom St Denis
*/

#ifdef LTC_LRW_MODE

/**
  Get the IV for LRW
  @param IV      [out] The IV, must be 16 octets
  @param len     Length ... must be at least 16 :-)
  @param lrw     The LRW state to read
  @return CRYPT_OK if successful
*/
int lrw_getiv(unsigned char *IV, unsigned long *len, const symmetric_LRW *lrw)
{
   LTC_ARGCHK(IV != NULL);
   LTC_ARGCHK(len != NULL);
   LTC_ARGCHK(lrw != NULL);
   if (*len < 16) {
       *len = 16;
       return CRYPT_BUFFER_OVERFLOW;
   }

   XMEMCPY(IV, lrw->IV, 16);
   *len = 16;
   return CRYPT_OK;
}

#endif
/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
