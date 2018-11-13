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

static const char * const _oid_pbes2 =  "1.2.840.113549.1.5.13";
static const char * const _oid_pbkdf2 = "1.2.840.113549.1.5.12";

typedef struct {
   const char *oid;
   const char *id;
} oid_id_st;

static const oid_id_st _hmac_oid_names[] = {
   { "1.2.840.113549.2.7",  "sha1" },
   { "1.2.840.113549.2.8",  "sha224" },
   { "1.2.840.113549.2.9",  "sha256" },
   { "1.2.840.113549.2.10", "sha384" },
   { "1.2.840.113549.2.11", "sha512" },
   { "1.2.840.113549.2.12", "sha512-224" },
   { "1.2.840.113549.2.13", "sha512-256" },
};

static const pbes_properties _pbes2_default_types[] = {
   { pkcs_5_alg2, "sha1",   "des",   8, 0 },
   { pkcs_5_alg2, "sha1",   "rc2",   4, 0 },
   { pkcs_5_alg2, "sha1",   "3des", 24, 0 },
   { pkcs_5_alg2, "sha1",   "aes",  16, 0 },
   { pkcs_5_alg2, "sha1",   "aes",  24, 0 },
   { pkcs_5_alg2, "sha1",   "aes",  32, 0 },
};

typedef struct {
   const pbes_properties *data;
   const char* oid;
} oid_to_pbes;

static const oid_to_pbes _pbes2_list[] = {
   { &_pbes2_default_types[0], "1.3.14.3.2.7"            },  /* http://www.oid-info.com/get/1.3.14.3.2.7            desCBC */
   { &_pbes2_default_types[1], "1.2.840.113549.3.2"      },  /* http://www.oid-info.com/get/1.2.840.113549.3.2      rc2CBC */
   { &_pbes2_default_types[2], "1.2.840.113549.3.7"      },  /* http://www.oid-info.com/get/1.2.840.113549.3.7      des-EDE3-CBC */
   { &_pbes2_default_types[3], "2.16.840.1.101.3.4.1.2"  },  /* http://www.oid-info.com/get/2.16.840.1.101.3.4.1.2  aes128-CBC */
   { &_pbes2_default_types[4], "2.16.840.1.101.3.4.1.22" },  /* http://www.oid-info.com/get/2.16.840.1.101.3.4.1.22 aes192-CBC */
   { &_pbes2_default_types[5], "2.16.840.1.101.3.4.1.42" },  /* http://www.oid-info.com/get/2.16.840.1.101.3.4.1.42 aes256-CBC */
};

static int _pbes2_from_oid(const ltc_asn1_list *cipher_oid, const ltc_asn1_list *hmac_oid, pbes_properties *res)
{
   unsigned int i;
   for (i = 0; i < sizeof(_pbes2_list)/sizeof(_pbes2_list[0]); ++i) {
      if (pk_oid_cmp_with_asn1(_pbes2_list[i].oid, cipher_oid) == CRYPT_OK) {
         *res = *_pbes2_list[i].data;
         break;
      }
   }
   if (res->c == NULL) return CRYPT_INVALID_CIPHER;
   if (hmac_oid != NULL) {
      for (i = 0; i < sizeof(_hmac_oid_names)/sizeof(_hmac_oid_names[0]); ++i) {
         if (pk_oid_cmp_with_asn1(_hmac_oid_names[i].oid, hmac_oid) == CRYPT_OK) {
            res->h = _hmac_oid_names[i].id;
            return CRYPT_OK;
         }
      }
      return CRYPT_INVALID_HASH;
   }
   return CRYPT_OK;
}


/**
   Extract PBES2 parameters

   @param s     The start of the sequence with potential PBES2 parameters
   @param res   Pointer to where the extracted parameters should be stored
   @return CRYPT_OK on success
*/
int pbes2_extract(const ltc_asn1_list *s, pbes_arg *res)
{
   unsigned long klen;
   ltc_asn1_list *lkdf, *lenc, *loptseq, *liter, *lhmac;
   int err;

   LTC_ARGCHK(s   != NULL);
   LTC_ARGCHK(res != NULL);

   if ((err = pk_oid_cmp_with_asn1(_oid_pbes2, s)) != CRYPT_OK) return err;

   if (!LTC_ASN1_IS_TYPE(s->next, LTC_ASN1_SEQUENCE) ||
       !LTC_ASN1_IS_TYPE(s->next->child, LTC_ASN1_SEQUENCE) ||
       !LTC_ASN1_IS_TYPE(s->next->child->child, LTC_ASN1_OBJECT_IDENTIFIER) ||
       !LTC_ASN1_IS_TYPE(s->next->child->child->next, LTC_ASN1_SEQUENCE) ||
       !LTC_ASN1_IS_TYPE(s->next->child->next, LTC_ASN1_SEQUENCE) ||
       !LTC_ASN1_IS_TYPE(s->next->child->next->child, LTC_ASN1_OBJECT_IDENTIFIER)) {
      return CRYPT_INVALID_PACKET;
   }
   /* PBES2: encrypted pkcs8 - PBES2+PBKDF2+des-ede3-cbc:
    *  0:d=0  hl=4 l= 380 cons: SEQUENCE
    *  4:d=1  hl=2 l=  78 cons:   SEQUENCE
    *  6:d=2  hl=2 l=   9 prim:     OBJECT             :PBES2 (== 1.2.840.113549.1.5.13) (== *s)
    * 17:d=2  hl=2 l=  65 cons:     SEQUENCE
    * 19:d=3  hl=2 l=  41 cons:       SEQUENCE
    * 21:d=4  hl=2 l=   9 prim:         OBJECT         :PBKDF2 (== *lkdf)
    * 32:d=4  hl=2 l=  28 cons:         SEQUENCE
    * 34:d=5  hl=2 l=   8 prim:           OCTET STRING [HEX DUMP]:28BA4ABF6AA76A3D (== res->salt)
    * 44:d=5  hl=2 l=   2 prim:           INTEGER      :0800 (== res->iterations, *liter)
    * 48:d=5  hl=2 l=  12 cons:           SEQUENCE     (== *loptseq   - this sequence is optional, may be missing)
    * 50:d=6  hl=2 l=   8 prim:             OBJECT     :hmacWithSHA256 (== *lhmac)
    * 60:d=6  hl=2 l=   0 prim:             NULL
    * 62:d=3  hl=2 l=  20 cons:       SEQUENCE
    * 64:d=4  hl=2 l=   8 prim:         OBJECT         :des-ede3-cbc (== *lenc)
    * 74:d=4  hl=2 l=   8 prim:         OCTET STRING   [HEX DUMP]:B1404C4688DC9A5A
    * 84:d=1  hl=4 l= 296 prim:   OCTET STRING         :bytes (== encrypted data)
    */
   lkdf = s->next->child->child;
   lenc = s->next->child->next->child;

   if ((err = pk_oid_cmp_with_asn1(_oid_pbkdf2, lkdf)) != CRYPT_OK) return err;

   if (!LTC_ASN1_IS_TYPE(lkdf->next, LTC_ASN1_SEQUENCE) ||
       !LTC_ASN1_IS_TYPE(lkdf->next->child, LTC_ASN1_OCTET_STRING) ||
       !LTC_ASN1_IS_TYPE(lkdf->next->child->next, LTC_ASN1_INTEGER)) {
      return CRYPT_INVALID_PACKET;
   }

   liter = lkdf->next->child->next;
   loptseq = liter->next;
   res->salt = lkdf->next->child;
   res->iterations = mp_get_int(liter->data);

   /* There's an optional INTEGER keyLength after the iterations, skip that if it's there.
    * c.f. RFC 2898 A.2 PBKDF2 */
   if(LTC_ASN1_IS_TYPE(loptseq, LTC_ASN1_INTEGER)) {
      loptseq = loptseq->next;
   }

   /* this sequence is optional */
   lhmac = NULL;
   if (LTC_ASN1_IS_TYPE(loptseq, LTC_ASN1_SEQUENCE) &&
       LTC_ASN1_IS_TYPE(loptseq->child, LTC_ASN1_OBJECT_IDENTIFIER)) {
      lhmac = loptseq->child;
   }
   if ((err = _pbes2_from_oid(lenc, lhmac, &res->type)) != CRYPT_OK) return err;

   if (LTC_ASN1_IS_TYPE(lenc->next, LTC_ASN1_OCTET_STRING)) {
      /* 'NON-RC2'-CBC */
      res->iv = lenc->next;
   } else if (LTC_ASN1_IS_TYPE(lenc->next, LTC_ASN1_SEQUENCE)) {
      /* RC2-CBC is a bit special ...
       *
       * RC2-CBC-Parameter ::= SEQUENCE {
       *     rc2ParameterVersion INTEGER OPTIONAL,
       *     iv OCTET STRING (SIZE(8)) }
       */
      if (LTC_ASN1_IS_TYPE(lenc->next->child, LTC_ASN1_INTEGER) &&
          LTC_ASN1_IS_TYPE(lenc->next->child->next, LTC_ASN1_OCTET_STRING)) {
         klen = mp_get_int(lenc->next->child->data);
         res->iv   = lenc->next->child->next;
         /*
          * Effective Key Bits         Encoding
          *         40                    160
          *         64                    120
          *        128                     58
          *       b >= 256                  b
          */
         switch (klen) {
            case 160:
               res->key_bits = 40;
               break;
            case 120:
               res->key_bits = 64;
               break;
            case 58:
               res->key_bits = 128;
               break;
            default:
               /* We don't handle undefined Key Bits */
               if (klen < 256) return CRYPT_INVALID_KEYSIZE;

               res->key_bits = klen;
               break;
         }
      } else if (LTC_ASN1_IS_TYPE(lenc->next->child, LTC_ASN1_OCTET_STRING)) {
         res->iv   = lenc->next->child;
         /*
          * If the rc2ParameterVersion field is omitted, the "effective key bits"
          * defaults to 32.
          */
         res->key_bits = 32;
      } else {
         return CRYPT_INVALID_PACKET;
      }
   }

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
