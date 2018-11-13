/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

/** Export raw public or private key (public keys = ANS X9.63 compressed or uncompressed; private keys = raw bytes)
  @param out    [out] destination of export
  @param outlen [in/out]  Length of destination and final output size
  @param type   PK_PRIVATE, PK_PUBLIC or PK_PUBLIC|PK_COMPRESSED
  @param key    Key to export
  Return        CRYPT_OK on success
*/

int ecc_get_key(unsigned char *out, unsigned long *outlen, int type, const ecc_key *key)
{
   unsigned long size, ksize;
   int err, compressed;

   LTC_ARGCHK(key    != NULL);
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   size = key->dp.size;
   compressed = type & PK_COMPRESSED ? 1 : 0;
   type &= ~PK_COMPRESSED;

   if (type == PK_PUBLIC) {
      if ((err = ltc_ecc_export_point(out, outlen, key->pubkey.x, key->pubkey.y, size, compressed)) != CRYPT_OK) {
         return err;
      }
   }
   else if (type == PK_PRIVATE) {
      if (key->type != PK_PRIVATE)                                                return CRYPT_PK_TYPE_MISMATCH;
      *outlen = size;
      if (size > *outlen)                                                         return CRYPT_BUFFER_OVERFLOW;
      if ((ksize = mp_unsigned_bin_size(key->k)) > size)                          return CRYPT_BUFFER_OVERFLOW;
      /* pad and store k */
      if ((err = mp_to_unsigned_bin(key->k, out + (size - ksize))) != CRYPT_OK)   return err;
      zeromem(out, size - ksize);
   }
   else {
      return CRYPT_INVALID_ARG;
   }

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
