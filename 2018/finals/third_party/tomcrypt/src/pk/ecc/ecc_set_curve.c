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

int ecc_set_curve(const ltc_ecc_curve *cu, ecc_key *key)
{
   int err;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(cu != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_read_radix(key->dp.prime, cu->prime, 16)) != CRYPT_OK) { goto error; }
   if ((err = mp_read_radix(key->dp.order, cu->order, 16)) != CRYPT_OK) { goto error; }
   if ((err = mp_read_radix(key->dp.A, cu->A, 16)) != CRYPT_OK)         { goto error; }
   if ((err = mp_read_radix(key->dp.B, cu->B, 16)) != CRYPT_OK)         { goto error; }
   if ((err = mp_read_radix(key->dp.base.x, cu->Gx, 16)) != CRYPT_OK)   { goto error; }
   if ((err = mp_read_radix(key->dp.base.y, cu->Gy, 16)) != CRYPT_OK)   { goto error; }
   if ((err = mp_set(key->dp.base.z, 1)) != CRYPT_OK)                   { goto error; }
   /* cofactor & size */
   key->dp.cofactor = cu->cofactor;
   key->dp.size = mp_unsigned_bin_size(key->dp.prime);
   /* OID string >> unsigned long oid[16] + oidlen */
   key->dp.oidlen = 16;
   if ((err = pk_oid_str_to_num(cu->OID, key->dp.oid, &key->dp.oidlen)) != CRYPT_OK) { goto error; }
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

int ecc_set_curve_by_size(int size, ecc_key *key)
{
   const ltc_ecc_curve *cu = NULL;
   int err = CRYPT_ERROR;

   /* for compatibility with libtomcrypt-1.17 the sizes below must match the specific curves */
   if (size <= 14) {
      err = ecc_find_curve("SECP112R1", &cu);
   }
   else if (size <= 16) {
      err = ecc_find_curve("SECP128R1", &cu);
   }
   else if (size <= 20) {
      err = ecc_find_curve("SECP160R1", &cu);
   }
   else if (size <= 24) {
      err = ecc_find_curve("SECP192R1", &cu);
   }
   else if (size <= 28) {
      err = ecc_find_curve("SECP224R1", &cu);
   }
   else if (size <= 32) {
      err = ecc_find_curve("SECP256R1", &cu);
   }
   else if (size <= 48) {
      err = ecc_find_curve("SECP384R1", &cu);
   }
   else if (size <= 66) {
      err = ecc_find_curve("SECP521R1", &cu);
   }

   if (err == CRYPT_OK && cu != NULL) return ecc_set_curve(cu, key);

   return CRYPT_INVALID_ARG;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
