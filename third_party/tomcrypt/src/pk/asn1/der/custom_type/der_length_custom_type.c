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
  @file der_length_custom_type.c
  ASN.1 DER, length of a custom type, Steffen Jaeckel
*/

#ifdef LTC_DER

/**
   Get the length of a DER custom type

   This function is a bit special compared to the others, as it requires the
   root-ltc_asn1_list where the type is defined.

   @param root          The root of the struct to encode
   @param outlen        [out] The length required in octets to store it
   @param payloadlen    [out] The length of the payload in octets
   @return CRYPT_OK on success
*/
int der_length_custom_type(const ltc_asn1_list *root, unsigned long *outlen, unsigned long *payloadlen)
{
   int           err;
   const ltc_asn1_list *list;
   ltc_asn1_type type;
   unsigned long size, x, y, i, inlen, id_len;
   void          *data;

   LTC_ARGCHK(root    != NULL);
   LTC_ARGCHK(outlen  != NULL);

   /* get size of output that will be required */
   if ((err = der_length_asn1_identifier(root, &id_len)) != CRYPT_OK) {
      return err;
   }
   y = id_len;

   if (root->pc == LTC_ASN1_PC_PRIMITIVE) {
      list = root;
      inlen = 1;
   } else {
      list = root->data;
      inlen = root->size;
   }
   for (i = 0; i < inlen; i++) {
       if (root->pc == LTC_ASN1_PC_PRIMITIVE) {
          type = (ltc_asn1_type)list[i].used;
       } else {
          type = list[i].type;
       }
       size = list[i].size;
       data = list[i].data;

       if (type == LTC_ASN1_EOL) {
          break;
       }

       /* some items may be optional during import */
       if (!list[i].used && list[i].optional) continue;

       switch (type) {
           case LTC_ASN1_BOOLEAN:
              if ((err = der_length_boolean(&x)) != CRYPT_OK) {
                 goto LBL_ERR;
              }
              y += x;
              break;

           case LTC_ASN1_INTEGER:
               if ((err = der_length_integer(data, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_SHORT_INTEGER:
               if ((err = der_length_short_integer(*((unsigned long *)data), &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_BIT_STRING:
           case LTC_ASN1_RAW_BIT_STRING:
               if ((err = der_length_bit_string(size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_OCTET_STRING:
               if ((err = der_length_octet_string(size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_NULL:
               y += 2;
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               if ((err = der_length_object_identifier(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_IA5_STRING:
               if ((err = der_length_ia5_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_TELETEX_STRING:
               if ((err = der_length_teletex_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_PRINTABLE_STRING:
               if ((err = der_length_printable_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_UTCTIME:
               if ((err = der_length_utctime(data, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_GENERALIZEDTIME:
               if ((err = der_length_generalizedtime(data, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_UTF8_STRING:
               if ((err = der_length_utf8_string(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_CUSTOM_TYPE:
               if ((err = der_length_custom_type(&list[i], &x, NULL)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               if ((err = der_length_sequence(data, size, &x)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               y += x;
               break;

           case LTC_ASN1_CHOICE:
           case LTC_ASN1_EOL:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
   }

   if (root->pc == LTC_ASN1_PC_PRIMITIVE) {
      /* In case it's a PRIMITIVE element we're going
       * to only replace the identifier of the one element
       * by the custom identifier.
       */
      y -= 1;
      if (payloadlen != NULL) {
         *payloadlen = y - id_len;
      }
   } else {
      /* calc length of length */
      if ((err = der_length_asn1_length(y - id_len, &x)) != CRYPT_OK) {
         goto LBL_ERR;
      }
      if (payloadlen != NULL) {
         *payloadlen = y - id_len;
      }
      y += x;
   }

   /* store size */
   *outlen = y;

LBL_ERR:
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
