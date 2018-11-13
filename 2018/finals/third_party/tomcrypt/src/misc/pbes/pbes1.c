/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_PBES

static int _pkcs_5_alg1_wrap(const unsigned char *password, unsigned long password_len,
                              const unsigned char *salt,     unsigned long salt_len,
                              int iteration_count,  int hash_idx,
                              unsigned char *out,   unsigned long *outlen)
{
   LTC_UNUSED_PARAM(salt_len);
   return pkcs_5_alg1(password, password_len, salt, iteration_count, hash_idx, out, outlen);
}

static int _pkcs_12_wrap(const unsigned char *password, unsigned long password_len,
                              const unsigned char *salt,     unsigned long salt_len,
                              int iteration_count,  int hash_idx,
                              unsigned char *out,   unsigned long *outlen)
{
   int err;
   /* convert password to unicode/utf16-be */
   unsigned long pwlen = password_len * 2;
   unsigned char* pw;
   if (*outlen < 32) return CRYPT_INVALID_ARG;
   pw = XMALLOC(pwlen + 2);
   if (pw == NULL) return CRYPT_MEM;
   if ((err = pkcs12_utf8_to_utf16(password, password_len, pw, &pwlen)) != CRYPT_OK) goto LBL_ERROR;
   pw[pwlen++] = 0;
   pw[pwlen++] = 0;
   /* derive KEY */
   if ((err = pkcs12_kdf(hash_idx, pw, pwlen, salt, salt_len, iteration_count, 1, out, 24)) != CRYPT_OK) goto LBL_ERROR;
   /* derive IV */
   if ((err = pkcs12_kdf(hash_idx, pw, pwlen, salt, salt_len, iteration_count, 2, out+24, 8)) != CRYPT_OK) goto LBL_ERROR;

   *outlen = 32;
LBL_ERROR:
   zeromem(pw, pwlen);
   XFREE(pw);
   return err;
}

static const pbes_properties _pbes1_types[] = {
   { _pkcs_5_alg1_wrap, "md2",   "des",   8, 8 },
   { _pkcs_5_alg1_wrap, "md2",   "rc2",   8, 8 },
   { _pkcs_5_alg1_wrap, "md5",   "des",   8, 8 },
   { _pkcs_5_alg1_wrap, "md5",   "rc2",   8, 8 },
   { _pkcs_5_alg1_wrap, "sha1",  "des",   8, 8 },
   { _pkcs_5_alg1_wrap, "sha1",  "rc2",   8, 8 },
   { _pkcs_12_wrap,     "sha1",  "3des", 24, 8 },
};

typedef struct {
   const pbes_properties *data;
   const char *oid;
} oid_to_pbes;

static const oid_to_pbes _pbes1_list[] = {
   { &_pbes1_types[0], "1.2.840.113549.1.5.1"    },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.1    pbeWithMD2AndDES-CBC */
   { &_pbes1_types[1], "1.2.840.113549.1.5.4"    },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.4    pbeWithMD2AndRC2-CBC */
   { &_pbes1_types[2], "1.2.840.113549.1.5.3"    },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.3    pbeWithMD5AndDES-CBC */
   { &_pbes1_types[3], "1.2.840.113549.1.5.6"    },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.6    pbeWithMD5AndRC2-CBC */
   { &_pbes1_types[4], "1.2.840.113549.1.5.10"   },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.10   pbeWithSHA1AndDES-CBC */
   { &_pbes1_types[5], "1.2.840.113549.1.5.11"   },  /* http://www.oid-info.com/get/1.2.840.113549.1.5.11   pbeWithSHA1AndRC2-CBC */
   { &_pbes1_types[6], "1.2.840.113549.1.12.1.3" },  /* http://www.oid-info.com/get/1.2.840.113549.1.12.1.3 pbeWithSHAAnd3-KeyTripleDES-CBC */
   { 0 },
};

static int _pbes1_from_oid(const ltc_asn1_list *oid, pbes_properties *res)
{
   unsigned int i;
   for (i = 0; _pbes1_list[i].data != NULL; ++i) {
      if (pk_oid_cmp_with_asn1(_pbes1_list[i].oid, oid) == CRYPT_OK) {
         if (res != NULL) *res = *_pbes1_list[i].data;
         return CRYPT_OK;
      }
   }
   return CRYPT_INVALID_ARG;
}

/**
   Extract PBES1 parameters

   @param s     The start of the sequence with potential PBES1 parameters
   @param res   Pointer to where the extracted parameters should be stored
   @return CRYPT_OK on success
*/
int pbes1_extract(const ltc_asn1_list *s, pbes_arg *res)
{
   int err;

   LTC_ARGCHK(s   != NULL);
   LTC_ARGCHK(res != NULL);

   if ((err = _pbes1_from_oid(s, &res->type)) != CRYPT_OK) return err;

   if (!LTC_ASN1_IS_TYPE(s->next, LTC_ASN1_SEQUENCE) ||
       !LTC_ASN1_IS_TYPE(s->next->child, LTC_ASN1_OCTET_STRING) ||
       !LTC_ASN1_IS_TYPE(s->next->child->next, LTC_ASN1_INTEGER)) {
      return CRYPT_INVALID_PACKET;
   }
   /* PBES1: encrypted pkcs8 - pbeWithMD5AndDES-CBC:
    *  0:d=0  hl=4 l= 329 cons: SEQUENCE
    *  4:d=1  hl=2 l=  27 cons:   SEQUENCE
    *  6:d=2  hl=2 l=   9 prim:     OBJECT             :pbeWithMD5AndDES-CBC (== 1.2.840.113549.1.5.3) (== *s)
    * 17:d=2  hl=2 l=  14 cons:     SEQUENCE           (== *lalgparam)
    * 19:d=3  hl=2 l=   8 prim:       OCTET STRING     [HEX DUMP]:8EDF749A06CCDE51 (== salt)
    * 29:d=3  hl=2 l=   2 prim:       INTEGER          :0800  (== iterations)
    * 33:d=1  hl=4 l= 296 prim:   OCTET STRING         :bytes (== encrypted data)
    */
   res->salt = s->next->child;
   res->iterations = mp_get_int(s->next->child->next->data);

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
