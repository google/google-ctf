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
  @file der_encode_asn1_length.c
  ASN.1 DER, encode the ASN.1 length field, Steffen Jaeckel
*/

#ifdef LTC_DER
/**
  Encode the ASN.1 length field
  @param len      The length to encode
  @param out      Where to write the length field to
  @param outlen   [in/out] The size of out available/written
  @return CRYPT_OK if successful
*/
int der_encode_asn1_length(unsigned long len, unsigned char *out, unsigned long *outlen)
{
   unsigned long x, y;

   LTC_ARGCHK(outlen != NULL);

   x = len;
   y = 0;

   while(x != 0) {
      y++;
      x >>= 8;
   }
   if (y == 0) {
      return CRYPT_PK_ASN1_ERROR;
   }

   if (out == NULL) {
      if (len < 128) {
         x = y;
      } else {
         x = y + 1;
      }
   } else {
      if (*outlen < y) {
         return CRYPT_BUFFER_OVERFLOW;
      }
      x = 0;
      if (len < 128) {
         out[x++] = (unsigned char)len;
      } else if (len <= 0xffUL) {
         out[x++] = 0x81;
         out[x++] = (unsigned char)len;
      } else if (len <= 0xffffUL) {
         out[x++] = 0x82;
         out[x++] = (unsigned char)((len>>8UL)&255);
         out[x++] = (unsigned char)(len&255);
      } else if (len <= 0xffffffUL) {
         out[x++] = 0x83;
         out[x++] = (unsigned char)((len>>16UL)&255);
         out[x++] = (unsigned char)((len>>8UL)&255);
         out[x++] = (unsigned char)(len&255);
      #if ULONG_MAX != ULLONG_MAX
      } else {
         out[x++] = 0x84;
         out[x++] = (unsigned char)((len>>24UL)&255);
         out[x++] = (unsigned char)((len>>16UL)&255);
         out[x++] = (unsigned char)((len>>8UL)&255);
         out[x++] = (unsigned char)(len&255);
      }
      #else
      } else if (len <= 0xffffffffUL) {
         out[x++] = 0x84;
         out[x++] = (unsigned char)((len>>24UL)&255);
         out[x++] = (unsigned char)((len>>16UL)&255);
         out[x++] = (unsigned char)((len>>8UL)&255);
         out[x++] = (unsigned char)(len&255);
      } else if (len <= 0xffffffffffULL) {
         out[x++] = 0x85;
         out[x++] = (unsigned char)((len>>32ULL)&255);
         out[x++] = (unsigned char)((len>>24ULL)&255);
         out[x++] = (unsigned char)((len>>16ULL)&255);
         out[x++] = (unsigned char)((len>>8ULL)&255);
         out[x++] = (unsigned char)(len&255);
      } else if (len <= 0xffffffffffffULL) {
         out[x++] = 0x86;
         out[x++] = (unsigned char)((len>>40ULL)&255);
         out[x++] = (unsigned char)((len>>32ULL)&255);
         out[x++] = (unsigned char)((len>>24ULL)&255);
         out[x++] = (unsigned char)((len>>16ULL)&255);
         out[x++] = (unsigned char)((len>>8ULL)&255);
         out[x++] = (unsigned char)(len&255);
      } else if (len <= 0xffffffffffffffULL) {
         out[x++] = 0x87;
         out[x++] = (unsigned char)((len>>48ULL)&255);
         out[x++] = (unsigned char)((len>>40ULL)&255);
         out[x++] = (unsigned char)((len>>32ULL)&255);
         out[x++] = (unsigned char)((len>>24ULL)&255);
         out[x++] = (unsigned char)((len>>16ULL)&255);
         out[x++] = (unsigned char)((len>>8ULL)&255);
         out[x++] = (unsigned char)(len&255);
      } else {
         out[x++] = 0x88;
         out[x++] = (unsigned char)((len>>56ULL)&255);
         out[x++] = (unsigned char)((len>>48ULL)&255);
         out[x++] = (unsigned char)((len>>40ULL)&255);
         out[x++] = (unsigned char)((len>>32ULL)&255);
         out[x++] = (unsigned char)((len>>24ULL)&255);
         out[x++] = (unsigned char)((len>>16ULL)&255);
         out[x++] = (unsigned char)((len>>8ULL)&255);
         out[x++] = (unsigned char)(len&255);
      }
      #endif
   }
   *outlen = x;

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
