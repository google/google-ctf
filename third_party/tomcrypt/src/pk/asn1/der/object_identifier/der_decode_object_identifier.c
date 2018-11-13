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
  @file der_decode_object_identifier.c
  ASN.1 DER, Decode Object Identifier, Tom St Denis
*/

#ifdef LTC_DER
/**
  Decode OID data and store the array of integers in words
  @param in      The OID DER encoded data
  @param inlen   The length of the OID data
  @param words   [out] The destination of the OID words
  @param outlen  [in/out] The number of OID words
  @return CRYPT_OK if successful
*/
int der_decode_object_identifier(const unsigned char *in,    unsigned long  inlen,
                                       unsigned long *words, unsigned long *outlen)
{
   unsigned long x, y, t, len;
   int err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(words  != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* header is at least 3 bytes */
   if (inlen < 3) {
      return CRYPT_INVALID_PACKET;
   }

   /* must be room for at least two words */
   if (*outlen < 2) {
      *outlen = 2;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* decode the packet header */
   x = 0;
   if ((in[x++] & 0x1F) != 0x06) {
      return CRYPT_INVALID_PACKET;
   }

   /* get the length of the data */
   y = inlen - x;
   if ((err = der_decode_asn1_length(in + x, &y, &len)) != CRYPT_OK) {
      return err;
   }
   x += y;

   if ((len == 0) || (len > (inlen - x))) {
      return CRYPT_INVALID_PACKET;
   }

   /* decode words */
   y = 0;
   t = 0;
   while (len--) {
      t = (t << 7) | (in[x] & 0x7F);
      if (!(in[x++] & 0x80)) {
         /* store t */
         if (y >= *outlen) {
            y++;
         } else {
            if (y == 0) {
               if (t <= 79) {
                  words[0] = t / 40;
                  words[1] = t % 40;
               } else {
                  words[0] = 2;
                  words[1] = t - 80;
               }
               y = 2;
            } else {
               words[y++] = t;
            }
         }
         t = 0;
      }
   }

   if (y > *outlen) {
      err =  CRYPT_BUFFER_OVERFLOW;
   } else {
      err =  CRYPT_OK;
   }

   *outlen = y;
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
