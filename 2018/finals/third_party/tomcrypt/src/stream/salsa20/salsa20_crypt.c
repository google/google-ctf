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

#define QUARTERROUND(a,b,c,d) \
    x[b] ^= (ROL((x[a] + x[d]),  7)); \
    x[c] ^= (ROL((x[b] + x[a]),  9)); \
    x[d] ^= (ROL((x[c] + x[b]), 13)); \
    x[a] ^= (ROL((x[d] + x[c]), 18));

static void _salsa20_block(unsigned char *output, const ulong32 *input, int rounds)
{
   ulong32 x[16];
   int i;
   XMEMCPY(x, input, sizeof(x));
   for (i = rounds; i > 0; i -= 2) {
      QUARTERROUND( 0, 4, 8,12)
      QUARTERROUND( 5, 9,13, 1)
      QUARTERROUND(10,14, 2, 6)
      QUARTERROUND(15, 3, 7,11)
      QUARTERROUND( 0, 1, 2, 3)
      QUARTERROUND( 5, 6, 7, 4)
      QUARTERROUND(10,11, 8, 9)
      QUARTERROUND(15,12,13,14)
   }
   for (i = 0; i < 16; ++i) {
     x[i] += input[i];
     STORE32L(x[i], output + 4 * i);
   }
}

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with Salsa20
   @param st      The Salsa20 state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return CRYPT_OK if successful
*/
int salsa20_crypt(salsa20_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out)
{
   unsigned char buf[64];
   unsigned long i, j;

   if (inlen == 0) return CRYPT_OK; /* nothing to do */

   LTC_ARGCHK(st        != NULL);
   LTC_ARGCHK(in        != NULL);
   LTC_ARGCHK(out       != NULL);
   LTC_ARGCHK(st->ivlen == 8 || st->ivlen == 24);

   if (st->ksleft > 0) {
      j = MIN(st->ksleft, inlen);
      for (i = 0; i < j; ++i, st->ksleft--) out[i] = in[i] ^ st->kstream[64 - st->ksleft];
      inlen -= j;
      if (inlen == 0) return CRYPT_OK;
      out += j;
      in  += j;
   }
   for (;;) {
     _salsa20_block(buf, st->input, st->rounds);
     /* Salsa20: 64-bit IV, increment 64-bit counter */
     if (0 == ++st->input[8] && 0 == ++st->input[9]) return CRYPT_OVERFLOW;
     if (inlen <= 64) {
       for (i = 0; i < inlen; ++i) out[i] = in[i] ^ buf[i];
       st->ksleft = 64 - inlen;
       for (i = inlen; i < 64; ++i) st->kstream[i] = buf[i];
       return CRYPT_OK;
     }
     for (i = 0; i < 64; ++i) out[i] = in[i] ^ buf[i];
     inlen -= 64;
     out += 64;
     in  += 64;
   }
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
