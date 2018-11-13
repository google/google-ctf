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
  @file ecc_make_key.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Make a new ECC key
  @param prng         An active PRNG state
  @param wprng        The index of the PRNG you wish to use
  @param keysize      The keysize for the new key (in octets from 20 to 65 bytes)
  @param key          [out] Destination of the newly created key
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_make_key(prng_state *prng, int wprng, int keysize, ecc_key *key)
{
   int err;

   if ((err = ecc_set_curve_by_size(keysize, key)) != CRYPT_OK) { return err; }
   if ((err = ecc_generate_key(prng, wprng, key)) != CRYPT_OK)  { return err; }
   return CRYPT_OK;
}

int ecc_make_key_ex(prng_state *prng, int wprng, ecc_key *key, const ltc_ecc_curve *cu)
{
   int err;
   if ((err = ecc_set_curve(cu, key)) != CRYPT_OK)             { return err; }
   if ((err = ecc_generate_key(prng, wprng, key)) != CRYPT_OK) { return err; }
   return CRYPT_OK;
}

int ecc_generate_key(prng_state *prng, int wprng, ecc_key *key)
{
   int            err;

   LTC_ARGCHK(ltc_mp.name != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(key->dp.size > 0);

   /* ECC key pair generation according to FIPS-186-4 (B.4.2 Key Pair Generation by Testing Candidates):
    * the generated private key k should be the range [1, order-1]
    *  a/ N = bitlen(order)
    *  b/ generate N random bits and convert them into big integer k
    *  c/ if k not in [1, order-1] go to b/
    *  e/ Q = k*G
    */
   if ((err = rand_bn_upto(key->k, key->dp.order, prng, wprng)) != CRYPT_OK) {
      goto error;
   }

   /* make the public key */
   if ((err = ltc_mp.ecc_ptmul(key->k, &key->dp.base, &key->pubkey, key->dp.A, key->dp.prime, 1)) != CRYPT_OK) {
      goto error;
   }
   key->type = PK_PRIVATE;

   /* success */
   err = CRYPT_OK;
   goto cleanup;

error:
   ecc_free(key);
cleanup:
   return err;
}

#endif
/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */

