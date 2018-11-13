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

static int _ecc_import_x509_with_oid(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   unsigned char bin_xy[2*ECC_MAXSIZE+2];
   unsigned long curveoid[16];
   unsigned long len_xy, len_oid, len;
   char OID[256];
   const ltc_ecc_curve *curve;
   int err;

   len_xy = sizeof(bin_xy);
   len_oid = 16;
   err = x509_decode_subject_public_key_info(in, inlen, PKA_EC, bin_xy, &len_xy,
                                             LTC_ASN1_OBJECT_IDENTIFIER, (void *)curveoid, &len_oid);
   if (err == CRYPT_OK) {
      /* load curve parameters for given curve OID */
      len = sizeof(OID);
      if ((err = pk_oid_num_to_str(curveoid, len_oid, OID, &len)) != CRYPT_OK) { goto error; }
      if ((err = ecc_find_curve(OID, &curve)) != CRYPT_OK)                     { goto error; }
      if ((err = ecc_set_curve(curve, key)) != CRYPT_OK)                       { goto error; }
      /* load public key */
      err = ecc_set_key(bin_xy, len_xy, PK_PUBLIC, key);
   }
error:
   return err;
}

static int _ecc_import_x509_with_curve(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   void *prime, *order, *a, *b, *gx, *gy;
   ltc_asn1_list seq_fieldid[2], seq_curve[3], seq_ecparams[6];
   unsigned char bin_a[ECC_MAXSIZE], bin_b[ECC_MAXSIZE];
   unsigned char bin_g[2*ECC_MAXSIZE+1], bin_xy[2*ECC_MAXSIZE+2], bin_seed[128];
   unsigned long len_a, len_b, len_g, len_xy, len;
   unsigned long cofactor = 0, ecver = 0, tmpoid[16];
   int err;

   if ((err = mp_init_multi(&prime, &order, &a, &b, &gx, &gy, NULL)) != CRYPT_OK) {
      return err;
   }

   /* ECParameters SEQUENCE */
   LTC_SET_ASN1(seq_ecparams, 0, LTC_ASN1_SHORT_INTEGER,     &ecver,      1UL);
   LTC_SET_ASN1(seq_ecparams, 1, LTC_ASN1_SEQUENCE,          seq_fieldid, 2UL);
   LTC_SET_ASN1(seq_ecparams, 2, LTC_ASN1_SEQUENCE,          seq_curve,   3UL);
   LTC_SET_ASN1(seq_ecparams, 3, LTC_ASN1_OCTET_STRING,      bin_g,       sizeof(bin_g));
   LTC_SET_ASN1(seq_ecparams, 4, LTC_ASN1_INTEGER,           order,       1UL);
   LTC_SET_ASN1(seq_ecparams, 5, LTC_ASN1_SHORT_INTEGER,     &cofactor,   1UL);
   seq_ecparams[5].optional = 1;
   /* FieldID SEQUENCE */
   LTC_SET_ASN1(seq_fieldid,  0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid,      16UL);
   LTC_SET_ASN1(seq_fieldid,  1, LTC_ASN1_INTEGER,           prime,       1UL);
   /* Curve SEQUENCE */
   LTC_SET_ASN1(seq_curve,    0, LTC_ASN1_OCTET_STRING,      bin_a,       sizeof(bin_a));
   LTC_SET_ASN1(seq_curve,    1, LTC_ASN1_OCTET_STRING,      bin_b,       sizeof(bin_b));
   LTC_SET_ASN1(seq_curve,    2, LTC_ASN1_RAW_BIT_STRING,    bin_seed,    8u*sizeof(bin_seed));
   seq_curve[2].optional = 1;
   /* try to load public key */
   len_xy = sizeof(bin_xy);
   len = 6;
   err = x509_decode_subject_public_key_info(in, inlen, PKA_EC, bin_xy, &len_xy, LTC_ASN1_SEQUENCE, seq_ecparams, &len);

   if (err == CRYPT_OK) {
      len_a = seq_curve[0].size;
      len_b = seq_curve[1].size;
      len_g = seq_ecparams[3].size;
      /* create bignums */
      if ((err = mp_read_unsigned_bin(a, bin_a, len_a)) != CRYPT_OK)                           { goto error; }
      if ((err = mp_read_unsigned_bin(b, bin_b, len_b)) != CRYPT_OK)                           { goto error; }
      if ((err = ltc_ecc_import_point(bin_g, len_g, prime, a, b, gx, gy)) != CRYPT_OK)         { goto error; }
      /* load curve parameters */
      if ((err = ecc_set_curve_from_mpis(a, b, prime, order, gx, gy, cofactor, key)) != CRYPT_OK) { goto error; }
      /* load public key */
      err = ecc_set_key(bin_xy, len_xy, PK_PUBLIC, key);
   }
error:
   mp_clear_multi(prime, order, a, b, gx, gy, NULL);
   return err;
}

int ecc_import_subject_public_key_info(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   int err;

   if ((err = _ecc_import_x509_with_oid(in, inlen, key)) == CRYPT_OK) {
      goto success;
   }

   err = _ecc_import_x509_with_curve(in, inlen, key);

success:
   return err;
}

/**
  Import an ECC key from a X.509 certificate
  @param in      The packet to import from
  @param inlen   It's length (octets)
  @param key     [out] Destination for newly imported key
  @return CRYPT_OK if successful, upon error allocated memory is freed
*/
int ecc_import_x509(const unsigned char *in, unsigned long inlen, ecc_key *key)
{
   int           err;
   unsigned long len;
   ltc_asn1_list *decoded_list = NULL, *l;

   LTC_ARGCHK(in  != NULL);
   LTC_ARGCHK(key != NULL);

   len = inlen;
   if ((err = der_decode_sequence_flexi(in, &len, &decoded_list)) == CRYPT_OK) {
      err = CRYPT_ERROR;
      l = decoded_list;
      if (l->type == LTC_ASN1_SEQUENCE &&
          l->child && l->child->type == LTC_ASN1_SEQUENCE) {
         l = l->child->child;
         while (l) {
            if (l->type == LTC_ASN1_SEQUENCE && l->data &&
                l->child && l->child->type == LTC_ASN1_SEQUENCE &&
                l->child->child && l->child->child->type == LTC_ASN1_OBJECT_IDENTIFIER &&
                l->child->next && l->child->next->type == LTC_ASN1_BIT_STRING) {
               err = ecc_import_subject_public_key_info(l->data, l->size, key);
               goto LBL_DONE;
            }
            l = l->next;
         }
      }
   }

LBL_DONE:
   if (decoded_list) der_free_sequence_flexi(decoded_list);
   return err;
}

#endif /* LTC_MECC */


/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
