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
  @file ecc_shared_secret.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Create an ECC shared secret between two keys
  @param private_key      The private ECC key
  @param public_key       The public key
  @param out              [out] Destination of the shared secret (Conforms to EC-DH from ANSI X9.63)
  @param outlen           [in/out] The max size and resulting size of the shared secret
  @return CRYPT_OK if successful
*/
int ecc_shared_secret(const ecc_key *private_key, const ecc_key *public_key,
                      unsigned char *out, unsigned long *outlen)
{
   unsigned long  x;
   ecc_point     *result;
   void          *prime, *a;
   int            err;

   LTC_ARGCHK(private_key != NULL);
   LTC_ARGCHK(public_key  != NULL);
   LTC_ARGCHK(out         != NULL);
   LTC_ARGCHK(outlen      != NULL);

   /* type valid? */
   if (private_key->type != PK_PRIVATE) {
      return CRYPT_PK_NOT_PRIVATE;
   }

   /* make new point */
   result = ltc_ecc_new_point();
   if (result == NULL) {
      return CRYPT_MEM;
   }

   prime = private_key->dp.prime;
   a     = private_key->dp.A;

   if ((err = ltc_mp.ecc_ptmul(private_key->k, &public_key->pubkey, result, a, prime, 1)) != CRYPT_OK)   { goto done; }

   x = (unsigned long)mp_unsigned_bin_size(prime);
   if (*outlen < x) {
      *outlen = x;
      err = CRYPT_BUFFER_OVERFLOW;
      goto done;
   }
   zeromem(out, x);
   if ((err = mp_to_unsigned_bin(result->x, out + (x - mp_unsigned_bin_size(result->x))))   != CRYPT_OK) { goto done; }

   err     = CRYPT_OK;
   *outlen = x;
done:
   ltc_ecc_del_point(result);
   return err;
}

#endif
/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */

