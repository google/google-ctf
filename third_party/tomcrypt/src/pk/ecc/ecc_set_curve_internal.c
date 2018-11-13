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

static int _ecc_cmp_hex_bn(const char *left_hex, void *right_bn, void *tmp_bn)
{
   if (mp_read_radix(tmp_bn, left_hex, 16) != CRYPT_OK) return 0;
   if (mp_cmp(tmp_bn, right_bn) != LTC_MP_EQ)           return 0;
   return 1;
}

static void _ecc_oid_lookup(ecc_key *key)
{
   void *bn;
   const ltc_ecc_curve *curve;

   key->dp.oidlen = 0;
   if (mp_init(&bn) != CRYPT_OK) return;
   for (curve = ltc_ecc_curves; curve->prime != NULL; curve++) {
      if (_ecc_cmp_hex_bn(curve->prime, key->dp.prime,  bn) != 1) continue;
      if (_ecc_cmp_hex_bn(curve->order, key->dp.order,  bn) != 1) continue;
      if (_ecc_cmp_hex_bn(curve->A,     key->dp.A,      bn) != 1) continue;
      if (_ecc_cmp_hex_bn(curve->B,     key->dp.B,      bn) != 1) continue;
      if (_ecc_cmp_hex_bn(curve->Gx,    key->dp.base.x, bn) != 1) continue;
      if (_ecc_cmp_hex_bn(curve->Gy,    key->dp.base.y, bn) != 1) continue;
      if (key->dp.cofactor != curve->cofactor)                    continue;
      break; /* found */
   }
   mp_clear(bn);
   if (curve->prime && curve->OID) {
      key->dp.oidlen = 16; /* size of key->dp.oid */
      pk_oid_str_to_num(curve->OID, key->dp.oid, &key->dp.oidlen);
   }
}

int ecc_copy_curve(const ecc_key *srckey, ecc_key *key)
{
   unsigned long i;
   int err;

   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(srckey != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_copy(srckey->dp.prime,  key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.order,  key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.A,      key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(srckey->dp.B,      key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = ltc_ecc_copy_point(&srckey->dp.base, &key->dp.base)) != CRYPT_OK) { goto error; }
   /* cofactor & size */
   key->dp.cofactor = srckey->dp.cofactor;
   key->dp.size     = srckey->dp.size;
   /* OID */
   if (srckey->dp.oidlen > 0) {
     key->dp.oidlen = srckey->dp.oidlen;
     for (i = 0; i < key->dp.oidlen; i++) key->dp.oid[i] = srckey->dp.oid[i];
   }
   else {
     _ecc_oid_lookup(key); /* try to find OID in ltc_ecc_curves */
   }
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

int ecc_set_curve_from_mpis(void *a, void *b, void *prime, void *order, void *gx, void *gy, unsigned long cofactor, ecc_key *key)
{
   int err;

   LTC_ARGCHK(key   != NULL);
   LTC_ARGCHK(a     != NULL);
   LTC_ARGCHK(b     != NULL);
   LTC_ARGCHK(prime != NULL);
   LTC_ARGCHK(order != NULL);
   LTC_ARGCHK(gx    != NULL);
   LTC_ARGCHK(gy    != NULL);

   if ((err = mp_init_multi(&key->dp.prime, &key->dp.order, &key->dp.A, &key->dp.B,
                            &key->dp.base.x, &key->dp.base.y, &key->dp.base.z,
                            &key->pubkey.x, &key->pubkey.y, &key->pubkey.z, &key->k,
                            NULL)) != CRYPT_OK) {
      return err;
   }

   /* A, B, order, prime, Gx, Gy */
   if ((err = mp_copy(prime, key->dp.prime )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(order, key->dp.order )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(a,     key->dp.A     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(b,     key->dp.B     )) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(gx,    key->dp.base.x)) != CRYPT_OK) { goto error; }
   if ((err = mp_copy(gy,    key->dp.base.y)) != CRYPT_OK) { goto error; }
   if ((err = mp_set(key->dp.base.z, 1)) != CRYPT_OK)      { goto error; }
   /* cofactor & size */
   key->dp.cofactor = cofactor;
   key->dp.size = mp_unsigned_bin_size(prime);
   /* try to find OID in ltc_ecc_curves */
   _ecc_oid_lookup(key);
   /* success */
   return CRYPT_OK;

error:
   ecc_free(key);
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
