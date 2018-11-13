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
  @file rsa_export.c
  Export RSA PKCS keys, Tom St Denis
*/

#ifdef LTC_MRSA

/**
    This will export either an RSAPublicKey or RSAPrivateKey [defined in PKCS #1 v2.1]
    @param out       [out] Destination of the packet
    @param outlen    [in/out] The max size and resulting size of the packet
    @param type      The type of exported key (PK_PRIVATE or PK_PUBLIC)
    @param key       The RSA key to export
    @return CRYPT_OK if successful
*/
int rsa_export(unsigned char *out, unsigned long *outlen, int type, const rsa_key *key)
{
   unsigned long zero=0;
   int err, std;
   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);
   LTC_ARGCHK(key    != NULL);

   std = type & PK_STD;
   type &= ~PK_STD;

   if (type == PK_PRIVATE && key->type != PK_PRIVATE) {
      return CRYPT_PK_TYPE_MISMATCH;
   }

   if (type == PK_PRIVATE) {
      /* private key */
      /* output is
            Version, n, e, d, p, q, d mod (p-1), d mod (q - 1), 1/q mod p
       */
      return der_encode_sequence_multi(out, outlen,
                          LTC_ASN1_SHORT_INTEGER, 1UL, &zero,
                          LTC_ASN1_INTEGER, 1UL,  key->N,
                          LTC_ASN1_INTEGER, 1UL,  key->e,
                          LTC_ASN1_INTEGER, 1UL,  key->d,
                          LTC_ASN1_INTEGER, 1UL,  key->p,
                          LTC_ASN1_INTEGER, 1UL,  key->q,
                          LTC_ASN1_INTEGER, 1UL,  key->dP,
                          LTC_ASN1_INTEGER, 1UL,  key->dQ,
                          LTC_ASN1_INTEGER, 1UL,  key->qP,
                          LTC_ASN1_EOL,     0UL, NULL);
   }

   if (type == PK_PUBLIC) {
      /* public key */
      unsigned long tmplen, *ptmplen;
      unsigned char* tmp = NULL;

      if (std) {
          tmplen = (unsigned long)(mp_count_bits(key->N) / 8) * 2 + 8;
          tmp = XMALLOC(tmplen);
          ptmplen = &tmplen;
          if (tmp == NULL) {
              return CRYPT_MEM;
          }
      }
      else {
          tmp = out;
          ptmplen = outlen;
      }

      err = der_encode_sequence_multi(tmp, ptmplen,
                                 LTC_ASN1_INTEGER, 1UL,  key->N,
                                 LTC_ASN1_INTEGER, 1UL,  key->e,
                                 LTC_ASN1_EOL,     0UL, NULL);

      if ((err != CRYPT_OK) || !std) {
          goto finish;
      }

      err = x509_encode_subject_public_key_info(out, outlen,
        PKA_RSA, tmp, tmplen, LTC_ASN1_NULL, NULL, 0);

finish:
      if (tmp != out) XFREE(tmp);
      return err;
   }

   return CRYPT_INVALID_ARG;
}

#endif /* LTC_MRSA */

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
