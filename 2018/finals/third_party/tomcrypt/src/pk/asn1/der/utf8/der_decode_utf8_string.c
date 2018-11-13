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
  @file der_decode_utf8_string.c
  ASN.1 DER, encode a UTF8 STRING, Tom St Denis
*/


#ifdef LTC_DER

/**
  Store a UTF8 STRING
  @param in      The DER encoded UTF8 STRING
  @param inlen   The size of the DER UTF8 STRING
  @param out     [out] The array of utf8s stored (one per char)
  @param outlen  [in/out] The number of utf8s stored
  @return CRYPT_OK if successful
*/
int der_decode_utf8_string(const unsigned char *in,  unsigned long inlen,
                                       wchar_t *out, unsigned long *outlen)
{
   wchar_t       tmp;
   unsigned long x, y, z, len;
   int err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* must have header at least */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }

   /* check for 0x0C */
   if ((in[0] & 0x1F) != 0x0C) {
      return CRYPT_INVALID_PACKET;
   }
   x = 1;

   /* get the length of the data */
   y = inlen - x;
   if ((err = der_decode_asn1_length(in + x, &y, &len)) != CRYPT_OK) {
      return err;
   }
   x += y;

   if (len > (inlen - x)) {
      return CRYPT_INVALID_PACKET;
   }

   /* proceed to decode */
   for (y = 0; x < inlen; ) {
      /* get first byte */
      tmp = in[x++];

      /* count number of bytes */
      for (z = 0; (tmp & 0x80) && (z <= 4); z++, tmp = (tmp << 1) & 0xFF);

      if (z > 4 || (x + (z - 1) > inlen)) {
         return CRYPT_INVALID_PACKET;
      }

      /* decode, grab upper bits */
      tmp >>= z;

      /* grab remaining bytes */
      if (z > 1) { --z; }
      while (z-- != 0) {
         if ((in[x] & 0xC0) != 0x80) {
            return CRYPT_INVALID_PACKET;
         }
         tmp = (tmp << 6) | ((wchar_t)in[x++] & 0x3F);
      }

      if (y < *outlen) {
         out[y] = tmp;
      }
      y++;
   }
   if (y > *outlen) {
      err = CRYPT_BUFFER_OVERFLOW;
   } else {
      err = CRYPT_OK;
   }
   *outlen = y;

   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
