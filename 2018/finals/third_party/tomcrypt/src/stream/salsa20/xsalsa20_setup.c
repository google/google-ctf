/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* The implementation is based on:
 * "Extending the Salsa20 nonce", https://cr.yp.to/snuffle/xsalsa-20081128.pdf
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#include "tomcrypt.h"

#ifdef LTC_XSALSA20

static const char * const constants = "expand 32-byte k";

#define QUARTERROUND(a,b,c,d) \
    x[b] ^= (ROL((x[a] + x[d]),  7)); \
    x[c] ^= (ROL((x[b] + x[a]),  9)); \
    x[d] ^= (ROL((x[c] + x[b]), 13)); \
    x[a] ^= (ROL((x[d] + x[c]), 18));

/* use modified salsa20 doubleround (no final addition as in salsa20) */
static void _xsalsa20_doubleround(ulong32 *x, int rounds)
{
   int i;

   for (i = rounds; i > 0; i -= 2) {
      /* columnround */
      QUARTERROUND( 0, 4, 8,12)
      QUARTERROUND( 5, 9,13, 1)
      QUARTERROUND(10,14, 2, 6)
      QUARTERROUND(15, 3, 7,11)
      /* rowround */
      QUARTERROUND( 0, 1, 2, 3)
      QUARTERROUND( 5, 6, 7, 4)
      QUARTERROUND(10,11, 8, 9)
      QUARTERROUND(15,12,13,14)
   }
}

#undef QUARTERROUND

/**
   Initialize an XSalsa20 context
   @param st        [out] The destination of the XSalsa20 state
   @param key       The secret key
   @param keylen    The length of the secret key, must be 32 (octets)
   @param nonce     The nonce
   @param noncelen  The length of the nonce, must be 24 (octets)
   @param rounds    Number of rounds (must be evenly divisible by 2, default is 20)
   @return CRYPT_OK if successful
*/
int xsalsa20_setup(salsa20_state *st, const unsigned char *key, unsigned long keylen,
                                      const unsigned char *nonce, unsigned long noncelen,
                                      int rounds)
{
   const int sti[] = {0, 5, 10, 15, 6, 7, 8, 9};  /* indices used to build subkey fm x */
   ulong32       x[64];                           /* input to & output fm doubleround */
   unsigned char subkey[32];
   int i;

   LTC_ARGCHK(st        != NULL);
   LTC_ARGCHK(key       != NULL);
   LTC_ARGCHK(keylen    == 32);
   LTC_ARGCHK(nonce     != NULL);
   LTC_ARGCHK(noncelen  == 24);
   if (rounds == 0) rounds = 20;
   LTC_ARGCHK(rounds % 2 == 0);     /* number of rounds must be evenly divisible by 2 */

   /* load the state to "hash" the key */
   LOAD32L(x[ 0], constants +  0);
   LOAD32L(x[ 5], constants +  4);
   LOAD32L(x[10], constants +  8);
   LOAD32L(x[15], constants + 12);
   LOAD32L(x[ 1], key +  0);
   LOAD32L(x[ 2], key +  4);
   LOAD32L(x[ 3], key +  8);
   LOAD32L(x[ 4], key + 12);
   LOAD32L(x[11], key + 16);
   LOAD32L(x[12], key + 20);
   LOAD32L(x[13], key + 24);
   LOAD32L(x[14], key + 28);
   LOAD32L(x[ 6], nonce +  0);
   LOAD32L(x[ 7], nonce +  4);
   LOAD32L(x[ 8], nonce +  8);
   LOAD32L(x[ 9], nonce + 12);

   /* use modified salsa20 doubleround (no final addition) */
   _xsalsa20_doubleround(x, rounds);

   /* extract the subkey */
   for (i = 0; i < 8; ++i) {
     STORE32L(x[sti[i]], subkey + 4 * i);
   }

   /* load the final initial state */
   LOAD32L(st->input[ 0], constants +  0);
   LOAD32L(st->input[ 5], constants +  4);
   LOAD32L(st->input[10], constants +  8);
   LOAD32L(st->input[15], constants + 12);
   LOAD32L(st->input[ 1], subkey +  0);
   LOAD32L(st->input[ 2], subkey +  4);
   LOAD32L(st->input[ 3], subkey +  8);
   LOAD32L(st->input[ 4], subkey + 12);
   LOAD32L(st->input[11], subkey + 16);
   LOAD32L(st->input[12], subkey + 20);
   LOAD32L(st->input[13], subkey + 24);
   LOAD32L(st->input[14], subkey + 28);
   LOAD32L(st->input[ 6], &(nonce[16]) + 0);
   LOAD32L(st->input[ 7], &(nonce[16]) + 4);
   st->input[ 8] = 0;
   st->input[ 9] = 0;
   st->rounds = rounds;
   st->ksleft = 0;
   st->ivlen  = 24;           /* set switch to say nonce/IV has been loaded */

#ifdef LTC_CLEAN_STACK
   zeromem(x, sizeof(x));
   zeromem(subkey, sizeof(subkey));
#endif

   return CRYPT_OK;
}


#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
