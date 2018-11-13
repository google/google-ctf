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
  @file der_decode_asn1_identifier.c
  ASN.1 DER, decode the ASN.1 Identifier, Steffen Jaeckel
*/

#ifdef LTC_DER
/* c.f. X.680 & X.690, some decisions backed by X.690 ch. 10.2 */
static const unsigned char tag_constructed_map[] =
{
 /*  0 */
 255,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 /*  5 */
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 /* 10 */
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 /* 15 */
 255,
 LTC_ASN1_PC_CONSTRUCTED,
 LTC_ASN1_PC_CONSTRUCTED,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 /* 20 */
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 /* 25 */
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
 LTC_ASN1_PC_PRIMITIVE,
};
 static const unsigned long tag_constructed_map_sz = sizeof(tag_constructed_map)/sizeof(tag_constructed_map[0]);

/**
  Decode the ASN.1 Identifier
  @param id    Where to store the decoded Identifier
  @param in    Where to read the Identifier from
  @param inlen [in/out] The size of in available/read
  @return CRYPT_OK if successful
*/
int der_decode_asn1_identifier(const unsigned char *in, unsigned long *inlen, ltc_asn1_list *id)
{
   ulong64 tmp;
   unsigned long tag_len;
   int err;

   LTC_ARGCHK(id    != NULL);
   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);

   if (*inlen == 0) {
      return CRYPT_BUFFER_OVERFLOW;
   }

   tag_len = 1;
   id->klass = (in[0] >> 6) & 0x3;
   id->pc = (in[0] >> 5) & 0x1;
   id->tag = in[0] & 0x1f;

   err = CRYPT_OK;
   if (id->tag == 0x1f) {
      id->tag = 0;
      do {
         if (*inlen < tag_len) {
            /* break the loop and trigger the BOF error-code */
            tmp = 0xff;
            break;
         }
         id->tag <<= 7;
         id->tag |= in[tag_len] & 0x7f;
         tmp = in[tag_len] & 0x80;
         tag_len++;
      } while ((tmp != 0) && (tag_len < 10));

      if (tmp != 0) {
         err = CRYPT_BUFFER_OVERFLOW;
      } else if (id->tag < 0x1f) {
         err = CRYPT_PK_ASN1_ERROR;
      }
   }

   if (err != CRYPT_OK) {
      id->pc = 0;
      id->klass = 0;
      id->tag = 0;
   } else {
      *inlen = tag_len;
      if ((id->klass == LTC_ASN1_CL_UNIVERSAL) &&
            (id->tag < der_asn1_tag_to_type_map_sz) &&
            (id->tag < tag_constructed_map_sz) &&
            (id->pc == tag_constructed_map[id->tag])) {
         id->type = der_asn1_tag_to_type_map[id->tag];
      } else {
         if ((id->klass == LTC_ASN1_CL_UNIVERSAL) && (id->tag == 0)) {
            id->type = LTC_ASN1_EOL;
         } else {
            id->type = LTC_ASN1_CUSTOM_TYPE;
         }
      }
   }

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
