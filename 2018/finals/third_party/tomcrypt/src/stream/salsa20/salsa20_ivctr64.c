/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* The implementation is based on:
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#include "tomcrypt_private.h"

#ifdef LTC_SALSA20

/**
  Set IV + counter data to the Salsa20 state
  @param st      The Salsa20 state
  @param iv      The IV data to add
  @param ivlen   The length of the IV (must be 8)
  @param counter 64bit (unsigned) initial counter value
  @return CRYPT_OK on success
 */
int salsa20_ivctr64(salsa20_state *st, const unsigned char *iv, unsigned long ivlen, ulong64 counter)
{
   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(iv != NULL);
   /* Salsa20: 64-bit IV (nonce) + 64-bit counter */
   LTC_ARGCHK(ivlen == 8);

   LOAD32L(st->input[6], iv + 0);
   LOAD32L(st->input[7], iv + 4);
   st->input[8] = (ulong32)(counter & 0xFFFFFFFF);
   st->input[9] = (ulong32)(counter >> 32);
   st->ksleft = 0;
   st->ivlen = ivlen;
   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
