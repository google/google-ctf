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
  @file der_encode_asn1_identifier.c
  ASN.1 DER, encode the ASN.1 Identifier, Steffen Jaeckel
*/

#ifdef LTC_DER
/**
  Encode the ASN.1 Identifier
  @param id       The ASN.1 Identifer to encode
  @param out      Where to write the identifier to
  @param outlen   [in/out] The size of out available/written
  @return CRYPT_OK if successful
*/
int der_encode_asn1_identifier(const ltc_asn1_list *id, unsigned char *out, unsigned long *outlen)
{
   ulong64 tmp;
   unsigned long tag_len;

   LTC_ARGCHK(id  != NULL);
   LTC_ARGCHK(outlen != NULL);

   if (id->type != LTC_ASN1_CUSTOM_TYPE) {
      if ((unsigned)id->type >= der_asn1_type_to_identifier_map_sz) {
         return CRYPT_INVALID_ARG;
      }
      if (der_asn1_type_to_identifier_map[id->type] == -1) {
         return CRYPT_INVALID_ARG;
      }
      if (out != NULL) {
         *out = der_asn1_type_to_identifier_map[id->type];
      }
      *outlen = 1;
      return CRYPT_OK;
   }
   if (id->klass < LTC_ASN1_CL_UNIVERSAL || id->klass > LTC_ASN1_CL_PRIVATE) {
      return CRYPT_INVALID_ARG;
   }
   if (id->pc < LTC_ASN1_PC_PRIMITIVE || id->pc > LTC_ASN1_PC_CONSTRUCTED) {
      return CRYPT_INVALID_ARG;
   }
   if (id->tag > (ULONG_MAX >> (8 + 7))) {
      return CRYPT_INVALID_ARG;
   }

   if (out != NULL) {
      if (*outlen < 1) {
         return CRYPT_BUFFER_OVERFLOW;
      }

      out[0] = id->klass << 6 | id->pc << 5;
   }

   if (id->tag < 0x1f) {
      if (out != NULL) {
         out[0] |= id->tag & 0x1f;
      }
      *outlen = 1;
   } else {
      tag_len = 0;
      tmp = id->tag;
      do {
         tag_len++;
         tmp >>= 7;
      } while (tmp);

      if (out != NULL) {
         if (*outlen < tag_len + 1) {
            return CRYPT_BUFFER_OVERFLOW;
         }
         out[0] |= 0x1f;
         for (tmp = 1; tmp <= tag_len; ++tmp) {
            out[tmp] = ((id->tag >> (7 * (tag_len - tmp))) & 0x7f) | 0x80;
         }
         out[tag_len] &= ~0x80;
      }
      *outlen = tag_len + 1;
   }

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
