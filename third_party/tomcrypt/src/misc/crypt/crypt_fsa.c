/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"
#include <stdarg.h>

/**
  @file crypt_fsa.c
  LibTomCrypt FULL SPEED AHEAD!, Tom St Denis
*/

/* format is ltc_mp, cipher_desc, [cipher_desc], NULL, hash_desc, [hash_desc], NULL, prng_desc, [prng_desc], NULL */
int crypt_fsa(void *mp, ...)
{
   va_list  args;
   void     *p;

   va_start(args, mp);
   if (mp != NULL) {
      XMEMCPY(&ltc_mp, mp, sizeof(ltc_mp));
   }

   while ((p = va_arg(args, void*)) != NULL) {
      if (register_cipher(p) == -1) {
         va_end(args);
         return CRYPT_INVALID_CIPHER;
      }
   }

   while ((p = va_arg(args, void*)) != NULL) {
      if (register_hash(p) == -1) {
         va_end(args);
         return CRYPT_INVALID_HASH;
      }
   }

   while ((p = va_arg(args, void*)) != NULL) {
      if (register_prng(p) == -1) {
         va_end(args);
         return CRYPT_INVALID_PRNG;
      }
   }

   va_end(args);
   return CRYPT_OK;
}


/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
