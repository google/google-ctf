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
   @file base16_decode.c
   Base16/Hex decode a string.
   Based on https://stackoverflow.com/a/23898449
   Adapted for libtomcrypt by Steffen Jaeckel
*/

#ifdef LTC_BASE16

/**
   Base16 decode a string
   @param in       The Base16 string to decode
   @param inlen    The length of the Base16 data
   @param out      [out] The destination of the binary decoded data
   @param outlen   [in/out] The max size and resulting size of the decoded data
   @return CRYPT_OK if successful
*/
int base16_decode(const          char *in,  unsigned long  inlen,
                        unsigned char *out, unsigned long *outlen)
{
   unsigned long pos, out_len;
   unsigned char idx0, idx1;
   char in0, in1;

   const unsigned char hashmap[] = {
         0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, /* 01234567 */
         0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* 89:;<=>? */
         0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, /* @ABCDEFG */
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* HIJKLMNO */
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* PQRSTUVW */
         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* XYZ[\]^_ */
         0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, /* `abcdefg */
   };

   LTC_ARGCHK(in     != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   if ((inlen % 2) == 1) return CRYPT_INVALID_PACKET;
   out_len = *outlen * 2;
   for (pos = 0; ((pos + 1 < out_len) && (pos + 1 < inlen)); pos += 2) {
      in0 = in[pos + 0];
      in1 = in[pos + 1];

      if ((in0 < '0') || (in0 > 'g')) return CRYPT_INVALID_PACKET;
      if ((in1 < '0') || (in1 > 'g')) return CRYPT_INVALID_PACKET;

      idx0 = (unsigned char) (in0 & 0x1F) ^ 0x10;
      idx1 = (unsigned char) (in1 & 0x1F) ^ 0x10;

      if (hashmap[idx0] == 0xff) return CRYPT_INVALID_PACKET;
      if (hashmap[idx1] == 0xff) return CRYPT_INVALID_PACKET;

      out[pos / 2] = (unsigned char) (hashmap[idx0] << 4) | hashmap[idx1];
   }
   *outlen = pos / 2;
   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
