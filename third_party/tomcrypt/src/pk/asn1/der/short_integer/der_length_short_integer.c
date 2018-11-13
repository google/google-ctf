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
  @file der_length_short_integer.c
  ASN.1 DER, get length of encoding, Tom St Denis
*/


#ifdef LTC_DER
/**
  Gets length of DER encoding of num
  @param num    The integer to get the size of
  @param outlen [out] The length of the DER encoding for the given integer
  @return CRYPT_OK if successful
*/
int der_length_short_integer(unsigned long num, unsigned long *outlen)
{
   unsigned long z, y;
   int err;

   LTC_ARGCHK(outlen  != NULL);

   /* force to 32 bits */
   num &= 0xFFFFFFFFUL;

   /* get the number of bytes */
   z = 0;
   y = num;
   while (y) {
     ++z;
     y >>= 8;
   }

   /* handle zero */
   if (z == 0) {
      z = 1;
   } else if ((num&(1UL<<((z<<3) - 1))) != 0) {
      /* in case msb is set */
      ++z;
   }

   if ((err = der_length_asn1_length(z, &y)) != CRYPT_OK) {
      return err;
   }
   *outlen = 1 + y + z;

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
