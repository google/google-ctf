/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_DER

/*
   Compare an OID string to an array of `unsigned long`.
   @return CRYPT_OK if equal
*/
int pk_oid_cmp_with_ulong(const char *o1, const unsigned long *o2, unsigned long o2size)
{
   unsigned long i;
   char tmp[256] = { 0 };
   int err;

   if (o1 == NULL || o2 == NULL) return CRYPT_ERROR;

   i = sizeof(tmp);
   if ((err = pk_oid_num_to_str(o2, o2size, tmp, &i)) != CRYPT_OK) {
      return err;
   }

   if (XSTRCMP(o1, tmp) != 0) {
      return CRYPT_PK_INVALID_TYPE;
   }

   return CRYPT_OK;
}

/*
   Compare an OID string to an OID element decoded from ASN.1.
   @return CRYPT_OK if equal
*/
int pk_oid_cmp_with_asn1(const char *o1, const ltc_asn1_list *o2)
{
   if (o1 == NULL || o2 == NULL) return CRYPT_ERROR;

   if (o2->type != LTC_ASN1_OBJECT_IDENTIFIER) return CRYPT_INVALID_ARG;

   return pk_oid_cmp_with_ulong(o1, o2->data, o2->size);
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
