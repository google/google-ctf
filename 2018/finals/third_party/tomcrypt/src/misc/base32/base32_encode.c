/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_BASE32

/**
   Base32 encode a buffer
   @param in       The input buffer to encode
   @param inlen    The length of the input buffer
   @param out      [out] The destination of the Base32 encoded data
   @param outlen   [in/out] The max size and resulting size of the encoded data
   @param id       Alphabet to use BASE32_RFC4648, BASE32_BASE32HEX, BASE32_ZBASE32 or BASE32_CROCKFORD
   @return CRYPT_OK if successful
*/
int base32_encode(const unsigned char *in,  unsigned long inlen,
                                 char *out, unsigned long *outlen,
                        base32_alphabet id)
{
   unsigned long i, x;
   const char *codes;
   const char *alphabet[4] = {
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",     /* id = BASE32_RFC4648   */
      "0123456789ABCDEFGHIJKLMNOPQRSTUV",     /* id = BASE32_BASE32HEX */
      "ybndrfg8ejkmcpqxot1uwisza345h769",     /* id = BASE32_ZBASE32   */
      "0123456789ABCDEFGHJKMNPQRSTVWXYZ"      /* id = BASE32_CROCKFORD */
   };

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(id >= BASE32_RFC4648);
   LTC_ARGCHK(id <= BASE32_CROCKFORD);

   /* check the size of output buffer +1 byte for terminating NUL */
   x = (8 * inlen + 4) / 5 + 1;
   if (*outlen < x) {
      *outlen = x;
      return CRYPT_BUFFER_OVERFLOW;
   }
   *outlen = x - 1; /* returning the length without terminating NUL */

   /* no input, nothing to do */
   if (inlen == 0) {
      *out = '\0';
      return CRYPT_OK;
   }

   codes = alphabet[id];
   x = 5 * (inlen / 5);
   for (i = 0; i < x; i += 5) {
      *out++ = codes[(in[0] >> 3) & 0x1F];
      *out++ = codes[(((in[0] & 0x7) << 2) + (in[1] >> 6)) & 0x1F];
      *out++ = codes[(in[1] >> 1) & 0x1F];
      *out++ = codes[(((in[1] & 0x1) << 4) + (in[2] >> 4)) & 0x1F];
      *out++ = codes[(((in[2] & 0xF) << 1) + (in[3] >> 7)) & 0x1F];
      *out++ = codes[(in[3] >> 2) & 0x1F];
      *out++ = codes[(((in[3] & 0x3) << 3) + (in[4] >> 5)) & 0x1F];
      *out++ = codes[in[4] & 0x1F];
      in += 5;
   }
   if (i < inlen) {
      unsigned a = in[0];
      unsigned b = (i+1 < inlen) ? in[1] : 0;
      unsigned c = (i+2 < inlen) ? in[2] : 0;
      unsigned d = (i+3 < inlen) ? in[3] : 0;
      *out++ = codes[(a >> 3) & 0x1F];
      *out++ = codes[(((a & 0x7) << 2) + (b >> 6)) & 0x1F];
      if (i+1 < inlen) {
         *out++ = codes[(b >> 1) & 0x1F];
         *out++ = codes[(((b & 0x1) << 4) + (c >> 4)) & 0x1F];
      }
      if (i+2 < inlen) {
         *out++ = codes[(((c & 0xF) << 1) + (d >> 7)) & 0x1F];
      }
      if (i+3 < inlen) {
         *out++ = codes[(d >> 2) & 0x1F];
         *out++ = codes[((d & 0x3) << 3) & 0x1F];
      }
   }
   *out = '\0';
   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
