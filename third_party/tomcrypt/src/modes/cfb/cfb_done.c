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
   @file cfb_done.c
   CFB implementation, finish chain, Tom St Denis
*/

#ifdef LTC_CFB_MODE

/** Terminate the chain
  @param cfb    The CFB chain to terminate
  @return CRYPT_OK on success
*/
int cfb_done(symmetric_CFB *cfb)
{
   int err;
   LTC_ARGCHK(cfb != NULL);

   if ((err = cipher_is_valid(cfb->cipher)) != CRYPT_OK) {
      return err;
   }
   cipher_descriptor[cfb->cipher].done(&cfb->key);
   return CRYPT_OK;
}



#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
