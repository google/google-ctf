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
  @file der_decode_integer.c
  ASN.1 DER, decode an integer, Tom St Denis
*/


#ifdef LTC_DER

/**
  Read a mp_int integer
  @param in       The DER encoded data
  @param inlen    Size of DER encoded data
  @param num      The first mp_int to decode
  @return CRYPT_OK if successful
*/
int der_decode_integer(const unsigned char *in, unsigned long inlen, void *num)
{
   unsigned long x, y;
   int           err;

   LTC_ARGCHK(num    != NULL);
   LTC_ARGCHK(in     != NULL);

   /* min DER INTEGER is 0x02 01 00 == 0 */
   if (inlen < (1 + 1 + 1)) {
      return CRYPT_INVALID_PACKET;
   }

   /* ok expect 0x02 when we AND with 0001 1111 [1F] */
   x = 0;
   if ((in[x++] & 0x1F) != 0x02) {
      return CRYPT_INVALID_PACKET;
   }

   /* get the length of the data */
   inlen -= x;
   if ((err = der_decode_asn1_length(in + x, &inlen, &y)) != CRYPT_OK) {
      return err;
   }
   x += inlen;

   if ((err = mp_read_unsigned_bin(num, (unsigned char *)in + x, y)) != CRYPT_OK) {
      return err;
   }

   /* see if it's negative */
   if (in[x] & 0x80) {
      void *tmp;
      if (mp_init(&tmp) != CRYPT_OK) {
         return CRYPT_MEM;
      }

      if (mp_2expt(tmp, mp_count_bits(num)) != CRYPT_OK || mp_sub(num, tmp, num) != CRYPT_OK) {
         mp_clear(tmp);
         return CRYPT_MEM;
      }
      mp_clear(tmp);
   }

   return CRYPT_OK;

}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
