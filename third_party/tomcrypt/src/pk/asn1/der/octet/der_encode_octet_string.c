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
  @file der_encode_octet_string.c
  ASN.1 DER, encode a OCTET STRING, Tom St Denis
*/


#ifdef LTC_DER

/**
  Store an OCTET STRING
  @param in       The array of OCTETS to store (one per char)
  @param inlen    The number of OCTETS to store
  @param out      [out] The destination for the DER encoded OCTET STRING
  @param outlen   [in/out] The max size and resulting size of the DER OCTET STRING
  @return CRYPT_OK if successful
*/
int der_encode_octet_string(const unsigned char *in, unsigned long inlen,
                                  unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y, len;
   int           err;

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* get the size */
   if ((err = der_length_octet_string(inlen, &len)) != CRYPT_OK) {
      return err;
   }

   /* too big? */
   if (len > *outlen) {
      *outlen = len;
      return CRYPT_BUFFER_OVERFLOW;
   }

   /* encode the header+len */
   x = 0;
   out[x++] = 0x04;
   len = *outlen - x;
   if ((err = der_encode_asn1_length(inlen, out + x, &len)) != CRYPT_OK) {
      return err;
   }
   x += len;

   /* store octets */
   for (y = 0; y < inlen; y++) {
       out[x++] = in[y];
   }

   /* retun length */
   *outlen = x;

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
