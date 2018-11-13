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
  @file der_encode_utf8_string.c
  ASN.1 DER, encode a UTF8 STRING, Tom St Denis
*/


#ifdef LTC_DER

/**
  Store an UTF8 STRING
  @param in       The array of UTF8 to store (one per wchar_t)
  @param inlen    The number of UTF8 to store
  @param out      [out] The destination for the DER encoded UTF8 STRING
  @param outlen   [in/out] The max size and resulting size of the DER UTF8 STRING
  @return CRYPT_OK if successful
*/
int der_encode_utf8_string(const wchar_t *in,  unsigned long inlen,
                           unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y, len;
   int err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* get the size */
   for (x = len = 0; x < inlen; x++) {
       if (!der_utf8_valid_char(in[x])) return CRYPT_INVALID_ARG;
       len += der_utf8_charsize(in[x]);
   }
   if ((err = der_length_asn1_length(len, &x)) != CRYPT_OK) {
      return err;
   }
   x += len + 1;

   /* too big? */
   if (x > *outlen) {
      *outlen = x;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* encode the header+len */
   x = 0;
   out[x++] = 0x0C;

   y = *outlen - x;
   if ((err = der_encode_asn1_length(len, out + x, &y)) != CRYPT_OK) {
      return err;
   }
   x += y;

   /* store UTF8 */
   for (y = 0; y < inlen; y++) {
       switch (der_utf8_charsize(in[y])) {
          case 1: out[x++] = (unsigned char)in[y]; break;
          case 2: out[x++] = 0xC0 | ((in[y] >> 6) & 0x1F);  out[x++] = 0x80 | (in[y] & 0x3F); break;
          case 3: out[x++] = 0xE0 | ((in[y] >> 12) & 0x0F); out[x++] = 0x80 | ((in[y] >> 6) & 0x3F); out[x++] = 0x80 | (in[y] & 0x3F); break;
#if !defined(LTC_WCHAR_MAX) || LTC_WCHAR_MAX > 0xFFFF
          case 4: out[x++] = 0xF0 | ((in[y] >> 18) & 0x07); out[x++] = 0x80 | ((in[y] >> 12) & 0x3F); out[x++] = 0x80 | ((in[y] >> 6) & 0x3F); out[x++] = 0x80 | (in[y] & 0x3F); break;
#endif
       }
   }

   /* return length */
   *outlen = x;

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
