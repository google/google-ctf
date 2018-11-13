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
   @file base16_encode.c
   Base16/Hex encode a string, Steffen Jaeckel
*/

#ifdef LTC_BASE16

/**
   Base16 encode a buffer
   @param in       The input buffer to encode
   @param inlen    The length of the input buffer
   @param out      [out] The destination of the Base16 encoded data
   @param outlen   [in/out] The max size and resulting size of the encoded data
   @param options  Output 'a-f' on 0 and 'A-F' otherwise.
   @return CRYPT_OK if successful
*/
int base16_encode(const unsigned char *in,  unsigned long  inlen,
                                 char *out, unsigned long *outlen,
                        unsigned int   options)
{
   unsigned long i, x;
   const char *alphabet;
   const char *alphabets[2] = {
      "0123456789abcdef",
      "0123456789ABCDEF",
   };

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* check the sizes */
   x = inlen * 2 + 1;

   if (x < inlen) return CRYPT_OVERFLOW;

   if (*outlen < x) {
      *outlen = x;
      return CRYPT_BUFFER_OVERFLOW;
   }
   x--;
   *outlen = x; /* returning the length without terminating NUL */

   if (options == 0) {
      alphabet = alphabets[0];
   } else {
      alphabet = alphabets[1];
   }

   for (i = 0; i < x; i += 2) {
      out[i]   = alphabet[(in[i/2] >> 4) & 0x0f];
      out[i+1] = alphabet[in[i/2] & 0x0f];
   }
   out[x] = '\0';

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
