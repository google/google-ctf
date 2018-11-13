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

/**
  Export an ECC key as a binary packet
  @param out     [out] Destination for the key
  @param outlen  [in/out] Max size and resulting size of the exported key
  @param type    The type of key you want to export (PK_PRIVATE or PK_PUBLIC)
  @param key     The key to export
  @return CRYPT_OK if successful
*/

int ecc_export_openssl(unsigned char *out, unsigned long *outlen, int type, const ecc_key *key)
{
   int           err;
   void *prime, *order, *a, *b, *gx, *gy;
   unsigned char bin_a[256], bin_b[256], bin_k[256], bin_g[512], bin_xy[512];
   unsigned long len_a, len_b, len_k, len_g, len_xy;
   unsigned long cofactor, one = 1;
   const char *OID;
   unsigned long oid[16], oidlen;
   ltc_asn1_list seq_fieldid[2], seq_curve[2], seq_ecparams[6], seq_priv[4], pub_xy, ecparams;
   int flag_oid = type & PK_CURVEOID ? 1 : 0;
   int flag_com = type & PK_COMPRESSED ? 1 : 0;
   int flag_pri = type & PK_PRIVATE ? 1 : 0;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   if (key->type != PK_PRIVATE && flag_pri) return CRYPT_PK_TYPE_MISMATCH;

   prime = key->dp.prime;
   order = key->dp.order;
   b     = key->dp.B;
   a     = key->dp.A;
   gx    = key->dp.base.x;
   gy    = key->dp.base.y;

   /* curve param a */
   len_a = mp_unsigned_bin_size(a);
   if (len_a > sizeof(bin_a))                                   { err = CRYPT_BUFFER_OVERFLOW; goto error; }
   if ((err = mp_to_unsigned_bin(a, bin_a)) != CRYPT_OK)        { goto error; }
   if (len_a == 0) { len_a = 1; bin_a[0] = 0; } /* handle case a == 0 */

   /* curve param b */
   len_b = mp_unsigned_bin_size(b);
   if (len_b > sizeof(bin_b))                                   { err = CRYPT_BUFFER_OVERFLOW; goto error; }
   if ((err = mp_to_unsigned_bin(b, bin_b)) != CRYPT_OK)        { goto error; }
   if (len_b == 0) { len_b = 1; bin_b[0] = 0; } /* handle case b == 0 */

   /* base point - (un)compressed based on flag_com */
   len_g = sizeof(bin_g);
   err = ltc_ecc_export_point(bin_g, &len_g, gx, gy, key->dp.size, flag_com);
   if (err != CRYPT_OK)                                         { goto error; }

   /* public key - (un)compressed based on flag_com */
   len_xy = sizeof(bin_xy);
   err = ltc_ecc_export_point(bin_xy, &len_xy, key->pubkey.x, key->pubkey.y, key->dp.size, flag_com);
   if (err != CRYPT_OK)                                         { goto error; }

   /* co-factor */
   cofactor = key->dp.cofactor;

   /* we support only prime-field EC */
   if ((err = pk_get_oid(PKA_EC_PRIMEF, &OID)) != CRYPT_OK)     { goto error; }

   if (flag_oid) {
      /* http://tools.ietf.org/html/rfc5912
         ECParameters ::= CHOICE {
           namedCurve      CURVE.&id({NamedCurve})                # OBJECT
         }
      */
      if (key->dp.oidlen == 0)                                  { err = CRYPT_INVALID_ARG; goto error; }
      LTC_SET_ASN1(&ecparams, 0, LTC_ASN1_OBJECT_IDENTIFIER, key->dp.oid, key->dp.oidlen);
   }
   else {
      /* http://tools.ietf.org/html/rfc3279
         ECParameters ::= SEQUENCE {                              # SEQUENCE
           version         INTEGER { ecpVer1(1) } (ecpVer1)       # INTEGER       :01
           FieldID ::= SEQUENCE {                                 # SEQUENCE
             fieldType       FIELD-ID.&id({IOSet}),               # OBJECT        :prime-field
             parameters      FIELD-ID.&Type({IOSet}{@fieldType})  # INTEGER
           }
           Curve ::= SEQUENCE {                                   # SEQUENCE
             a               FieldElement ::= OCTET STRING        # OCTET STRING
             b               FieldElement ::= OCTET STRING        # OCTET STRING
             seed            BIT STRING      OPTIONAL
           }
           base            ECPoint ::= OCTET STRING               # OCTET STRING
           order           INTEGER,                               # INTEGER
           cofactor        INTEGER OPTIONAL                       # INTEGER
         }
      */

      oidlen = sizeof(oid)/sizeof(oid[0]);
      if ((err = pk_oid_str_to_num(OID, oid, &oidlen)) != CRYPT_OK) {
         goto error;
      }

      /* FieldID SEQUENCE */
      LTC_SET_ASN1(seq_fieldid,  0, LTC_ASN1_OBJECT_IDENTIFIER, oid,         oidlen);
      LTC_SET_ASN1(seq_fieldid,  1, LTC_ASN1_INTEGER,           prime,       1UL);

      /* Curve SEQUENCE */
      LTC_SET_ASN1(seq_curve,    0, LTC_ASN1_OCTET_STRING,      bin_a,       len_a);
      LTC_SET_ASN1(seq_curve,    1, LTC_ASN1_OCTET_STRING,      bin_b,       len_b);

      /* ECParameters SEQUENCE */
      LTC_SET_ASN1(seq_ecparams, 0, LTC_ASN1_SHORT_INTEGER,     &one,        1UL);
      LTC_SET_ASN1(seq_ecparams, 1, LTC_ASN1_SEQUENCE,          seq_fieldid, 2UL);
      LTC_SET_ASN1(seq_ecparams, 2, LTC_ASN1_SEQUENCE,          seq_curve,   2UL);
      LTC_SET_ASN1(seq_ecparams, 3, LTC_ASN1_OCTET_STRING,      bin_g,       len_g);
      LTC_SET_ASN1(seq_ecparams, 4, LTC_ASN1_INTEGER,           order,       1UL);
      LTC_SET_ASN1(seq_ecparams, 5, LTC_ASN1_SHORT_INTEGER,     &cofactor,   1UL);

      /* ECParameters used by ECPrivateKey or SubjectPublicKeyInfo below */
      LTC_SET_ASN1(&ecparams,    0, LTC_ASN1_SEQUENCE, seq_ecparams, 6UL);
   }

   if (flag_pri) {
      /* http://tools.ietf.org/html/rfc5915
         ECPrivateKey ::= SEQUENCE {                                    # SEQUENCE
           version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1)  # INTEGER       :01
           privateKey     OCTET STRING,                                 # OCTET STRING
           [0] ECParameters                                             # see above
           [1] publicKey                                                # BIT STRING
         }
      */

      /* private key */
      len_k = mp_unsigned_bin_size(key->k);
      if (len_k > sizeof(bin_k))                                        { err = CRYPT_BUFFER_OVERFLOW; goto error; }
      if ((err = mp_to_unsigned_bin(key->k, bin_k)) != CRYPT_OK)        { goto error; }

      LTC_SET_ASN1(&pub_xy,  0, LTC_ASN1_RAW_BIT_STRING, bin_xy, 8*len_xy);
      LTC_SET_ASN1(seq_priv, 0, LTC_ASN1_SHORT_INTEGER,  &one,   1);
      LTC_SET_ASN1(seq_priv, 1, LTC_ASN1_OCTET_STRING,   bin_k,  len_k);
      LTC_SET_ASN1_CUSTOM_CONSTRUCTED(seq_priv, 2, LTC_ASN1_CL_CONTEXT_SPECIFIC, 0, &ecparams); /* context specific 0 */
      LTC_SET_ASN1_CUSTOM_CONSTRUCTED(seq_priv, 3, LTC_ASN1_CL_CONTEXT_SPECIFIC, 1, &pub_xy);   /* context specific 1 */

      err = der_encode_sequence(seq_priv, 4, out, outlen);
   }
   else {
      /* http://tools.ietf.org/html/rfc5480
         SubjectPublicKeyInfo ::= SEQUENCE  {                           # SEQUENCE
           AlgorithmIdentifier ::= SEQUENCE  {                          # SEQUENCE
             algorithm OBJECT IDENTIFIER                                # OBJECT        :id-ecPublicKey
             ECParameters                                               # see above
           }
           subjectPublicKey  BIT STRING                                 # BIT STRING
         }
      */
      err = x509_encode_subject_public_key_info( out, outlen, PKA_EC, bin_xy, len_xy,
                                                 ecparams.type, ecparams.data, ecparams.size );
   }

error:
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
