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
  @file ecc_import.c
  ECC Crypto, Tom St Denis
*/

#ifdef LTC_MECC

/**
  Import an ECC key from a binary packet
  @param in      The packet to import
  @param inlen   The length of the packet
  @param key     [out] The destination of the import
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_import(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   return ecc_import_ex(in, inlen, key, NULL);
}

/**
  Import an ECC key from a binary packet, using user supplied domain params rather than one of the NIST ones
  @param in      The packet to import
  @param inlen   The length of the packet
  @param key     [out] The destination of the import
  @param cu      pointer to user supplied params; must be the same as the params used when exporting
  @return CRYPT_OK if successful, upon error all allocated memory will be freed
*/
int ecc_import_ex(const unsigned char *in, unsigned long inlen, ecc_key *key, const ltc_ecc_curve *cu)
{
   unsigned long key_size;
   unsigned char flags[1];
   int           err;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* find out what type of key it is */
   err = der_decode_sequence_multi(in, inlen, LTC_ASN1_BIT_STRING,    1UL, flags,
                                              LTC_ASN1_SHORT_INTEGER, 1UL, &key_size,
                                              LTC_ASN1_EOL,           0UL, NULL);
   if (err != CRYPT_OK && err != CRYPT_INPUT_TOO_LONG) {
      return err;
   }

   /* allocate & initialize the key */
   if (cu == NULL) {
      if ((err = ecc_set_curve_by_size(key_size, key)) != CRYPT_OK) { goto done; }
   } else {
      if ((err = ecc_set_curve(cu, key)) != CRYPT_OK)               { goto done; }
   }

   if (flags[0] == 1) {
      /* private key */
      key->type = PK_PRIVATE;
      if ((err = der_decode_sequence_multi(in, inlen,
                                     LTC_ASN1_BIT_STRING,      1UL, flags,
                                     LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                     LTC_ASN1_INTEGER,         1UL, key->pubkey.x,
                                     LTC_ASN1_INTEGER,         1UL, key->pubkey.y,
                                     LTC_ASN1_INTEGER,         1UL, key->k,
                                     LTC_ASN1_EOL,             0UL, NULL)) != CRYPT_OK) {
         goto done;
      }
   } else if (flags[0] == 0) {
      /* public key */
      key->type = PK_PUBLIC;
      if ((err = der_decode_sequence_multi(in, inlen,
                                     LTC_ASN1_BIT_STRING,      1UL, flags,
                                     LTC_ASN1_SHORT_INTEGER,   1UL, &key_size,
                                     LTC_ASN1_INTEGER,         1UL, key->pubkey.x,
                                     LTC_ASN1_INTEGER,         1UL, key->pubkey.y,
                                     LTC_ASN1_EOL,             0UL, NULL)) != CRYPT_OK) {
         goto done;
      }
   }
   else {
      err = CRYPT_INVALID_PACKET;
      goto done;
   }

   /* set z */
   if ((err = mp_set(key->pubkey.z, 1)) != CRYPT_OK) { goto done; }

   /* point on the curve + other checks */
   if ((err = ltc_ecc_verify_key(key)) != CRYPT_OK)  { goto done; }

   /* we're good */
   return CRYPT_OK;

done:
   ecc_free(key);
   return err;
}
#endif
/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */

