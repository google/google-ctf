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
  @file der_encode_object_identifier.c
  ASN.1 DER, Encode Object Identifier, Tom St Denis
*/

#ifdef LTC_DER
/**
  Encode an OID
  @param words   The words to encode  (upto 32-bits each)
  @param nwords  The number of words in the OID
  @param out     [out] Destination of OID data
  @param outlen  [in/out] The max and resulting size of the OID
  @return CRYPT_OK if successful
*/
int der_encode_object_identifier(const unsigned long *words, unsigned long  nwords,
                                       unsigned char *out,   unsigned long *outlen)
{
   unsigned long i, x, y, z, t, mask, wordbuf;
   int           err;

   LTC_ARGCHK(words  != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* check length */
   if ((err = der_length_object_identifier(words, nwords, &x)) != CRYPT_OK) {
      return err;
   }
   if (x > *outlen) {
      *outlen = x;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* compute length to store OID data */
   z = 0;
   wordbuf = words[0] * 40 + words[1];
   for (y = 1; y < nwords; y++) {
       t = der_object_identifier_bits(wordbuf);
       z += t/7 + ((t%7) ? 1 : 0) + (wordbuf == 0 ? 1 : 0);
       if (y < nwords - 1) {
          wordbuf = words[y + 1];
       }
   }

   /* store header + length */
   x = 0;
   out[x++] = 0x06;
   y = *outlen - x;
   if ((err = der_encode_asn1_length(z, out + x, &y)) != CRYPT_OK) {
      return err;
   }
   x += y;

   /* store first byte */
   wordbuf = words[0] * 40 + words[1];
   for (i = 1; i < nwords; i++) {
      /* store 7 bit words in little endian */
      t    = wordbuf & 0xFFFFFFFF;
      if (t) {
         y    = x;
         mask = 0;
         while (t) {
            out[x++] = (unsigned char)((t & 0x7F) | mask);
            t    >>= 7;
            mask  |= 0x80;  /* upper bit is set on all but the last byte */
         }
         /* now swap bytes y...x-1 */
         z = x - 1;
         while (y < z) {
            t = out[y]; out[y] = out[z]; out[z] = (unsigned char)t;
            ++y;
            --z;
         }
      } else {
         /* zero word */
         out[x++] = 0x00;
      }

      if (i < nwords - 1) {
         wordbuf = words[i + 1];
      }
   }

   *outlen = x;
   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
