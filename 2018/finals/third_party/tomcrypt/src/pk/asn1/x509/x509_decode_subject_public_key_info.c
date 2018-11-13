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
  @file x509_decode_subject_public_key_info.c
  ASN.1 DER/X.509, encode a SubjectPublicKeyInfo structure --nmav
*/

#ifdef LTC_DER

/* AlgorithmIdentifier := SEQUENCE {
 *    algorithm OBJECT IDENTIFIER,
 *    parameters ANY DEFINED BY algorithm
 * }
 *
 * SubjectPublicKeyInfo := SEQUENCE {
 *    algorithm AlgorithmIdentifier,
 *    subjectPublicKey BIT STRING
 * }
 */
/**
  Decode a SubjectPublicKeyInfo
   @param in      The input buffer
   @param inlen   The length of the input buffer
   @param algorithm             One out of the enum #public_key_algorithms
   @param public_key            The buffer for the public key
   @param public_key_len        [in/out] The length of the public key buffer and the written length
   @param parameters_type       The parameters' type out of the enum ltc_asn1_type
   @param parameters            The parameters to include
   @param parameters_len        [in/out]The number of parameters to include
   @return CRYPT_OK on success
*/
int x509_decode_subject_public_key_info(const unsigned char *in, unsigned long inlen,
        unsigned int algorithm, void* public_key, unsigned long* public_key_len,
        ltc_asn1_type parameters_type, ltc_asn1_list* parameters, unsigned long *parameters_len)
{
   int err;
   unsigned long len, alg_id_num;
   const char* oid;
   unsigned char *tmpbuf;
   unsigned long  tmpoid[16];
   ltc_asn1_list alg_id[2];
   ltc_asn1_list subject_pubkey[2];

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != 0);
   LTC_ARGCHK(public_key_len != NULL);
   if (parameters_type != LTC_ASN1_EOL) {
      LTC_ARGCHK(parameters_len != NULL);
   }

   err = pk_get_oid(algorithm, &oid);
   if (err != CRYPT_OK) {
        return err;
   }

   /* see if the OpenSSL DER format RSA public key will work */
   tmpbuf = XCALLOC(1, inlen);
   if (tmpbuf == NULL) {
       err = CRYPT_MEM;
       goto LBL_ERR;
   }

   /* this includes the internal hash ID and optional params (NULL in this case) */
   LTC_SET_ASN1(alg_id, 0, LTC_ASN1_OBJECT_IDENTIFIER, tmpoid, sizeof(tmpoid)/sizeof(tmpoid[0]));
   if (parameters_type == LTC_ASN1_EOL) {
      alg_id_num = 1;
   }
   else {
      LTC_SET_ASN1(alg_id, 1, parameters_type, parameters, *parameters_len);
      alg_id_num = 2;
   }

   /* the actual format of the SSL DER key is odd, it stores a RSAPublicKey
    * in a **BIT** string ... so we have to extract it then proceed to convert bit to octet
    */
   LTC_SET_ASN1(subject_pubkey, 0, LTC_ASN1_SEQUENCE, alg_id, alg_id_num);
   LTC_SET_ASN1(subject_pubkey, 1, LTC_ASN1_RAW_BIT_STRING, tmpbuf, inlen*8U);

   err=der_decode_sequence(in, inlen, subject_pubkey, 2UL);
   if (err != CRYPT_OK) {
           goto LBL_ERR;
   }
   if (parameters_type != LTC_ASN1_EOL) {
      *parameters_len = alg_id[1].size;
   }

   if ((err = pk_oid_cmp_with_asn1(oid, &alg_id[0])) != CRYPT_OK) {
      /* OID mismatch */
      goto LBL_ERR;
   }

   len = subject_pubkey[1].size/8;
   if (*public_key_len >= len) {
       XMEMCPY(public_key, subject_pubkey[1].data, len);
       *public_key_len = len;
    } else {
        *public_key_len = len;
        err = CRYPT_BUFFER_OVERFLOW;
        goto LBL_ERR;
    }

    err = CRYPT_OK;

LBL_ERR:

    XFREE(tmpbuf);

    return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
