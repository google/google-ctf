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

static const char * const sigma = "expand 32-byte k";
static const char * const tau   = "expand 16-byte k";

/**
   Initialize an Salsa20 context (only the key)
   @param st        [out] The destination of the Salsa20 state
   @param key       The secret key
   @param keylen    The length of the secret key (octets)
   @param rounds    Number of rounds (e.g. 20 for Salsa20)
   @return CRYPT_OK if successful
*/
int salsa20_setup(salsa20_state *st, const unsigned char *key, unsigned long keylen, int rounds)
{
   const char *constants;

   LTC_ARGCHK(st  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(keylen == 32 || keylen == 16);

   if (rounds == 0) rounds = 20;
   LTC_ARGCHK(rounds % 2 == 0); /* number of rounds must be evenly divisible by 2 */

   LOAD32L(st->input[1],  key + 0);
   LOAD32L(st->input[2],  key + 4);
   LOAD32L(st->input[3],  key + 8);
   LOAD32L(st->input[4],  key + 12);
   if (keylen == 32) { /* 256bit */
      key += 16;
      constants = sigma;
   } else { /* 128bit */
      constants = tau;
   }
   LOAD32L(st->input[11], key + 0);
   LOAD32L(st->input[12], key + 4);
   LOAD32L(st->input[13], key + 8);
   LOAD32L(st->input[14], key + 12);
   LOAD32L(st->input[ 0],  constants + 0);
   LOAD32L(st->input[ 5],  constants + 4);
   LOAD32L(st->input[10],  constants + 8);
   LOAD32L(st->input[15],  constants + 12);
   st->rounds = rounds;     /* default is 20 for salsa20 */
   st->ivlen = 0;           /* will be set later by salsa20_ivctr(32|64) */
   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
