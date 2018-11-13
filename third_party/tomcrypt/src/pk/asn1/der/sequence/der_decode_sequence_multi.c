/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"
#include <stdarg.h>


/**
  @file der_decode_sequence_multi.c
  ASN.1 DER, decode a SEQUENCE, Tom St Denis
*/

#ifdef LTC_DER

/**
  Decode a SEQUENCE type using a VA list
  @param in    Input buffer
  @param inlen Length of input in octets
  @param a1    Initialized argument list #1
  @param a2    Initialized argument list #2 (copy of #1)
  @param flags    c.f. enum ltc_der_seq
  @return CRYPT_OK on success
*/
static int _der_decode_sequence_va(const unsigned char *in, unsigned long inlen, va_list a1, va_list a2, unsigned int flags)
{
   int           err;
   ltc_asn1_type type;
   unsigned long size, x;
   void          *data;
   ltc_asn1_list *list;

   LTC_ARGCHK(in    != NULL);

   /* get size of output that will be required */
   x = 0;
   for (;;) {
       type = (ltc_asn1_type)va_arg(a1, int);
       size = va_arg(a1, unsigned long);
       data = va_arg(a1, void*);
       LTC_UNUSED_PARAM(size);
       LTC_UNUSED_PARAM(data);

       if (type == LTC_ASN1_EOL) {
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
           case LTC_ASN1_INTEGER:
           case LTC_ASN1_SHORT_INTEGER:
           case LTC_ASN1_BIT_STRING:
           case LTC_ASN1_OCTET_STRING:
           case LTC_ASN1_NULL:
           case LTC_ASN1_OBJECT_IDENTIFIER:
           case LTC_ASN1_IA5_STRING:
           case LTC_ASN1_PRINTABLE_STRING:
           case LTC_ASN1_UTF8_STRING:
           case LTC_ASN1_UTCTIME:
           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
           case LTC_ASN1_CHOICE:
           case LTC_ASN1_RAW_BIT_STRING:
           case LTC_ASN1_TELETEX_STRING:
           case LTC_ASN1_GENERALIZEDTIME:
                ++x;
                break;

           case LTC_ASN1_EOL:
           case LTC_ASN1_CUSTOM_TYPE:
               return CRYPT_INVALID_ARG;
       }
   }

   /* allocate structure for x elements */
   if (x == 0) {
      return CRYPT_NOP;
   }

   list = XCALLOC(sizeof(*list), x);
   if (list == NULL) {
      return CRYPT_MEM;
   }

   /* fill in the structure */
   x = 0;
   for (;;) {
       type = (ltc_asn1_type)va_arg(a2, int);
       size = va_arg(a2, unsigned long);
       data = va_arg(a2, void*);

       if (type == LTC_ASN1_EOL) {
          break;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
           case LTC_ASN1_INTEGER:
           case LTC_ASN1_SHORT_INTEGER:
           case LTC_ASN1_BIT_STRING:
           case LTC_ASN1_OCTET_STRING:
           case LTC_ASN1_NULL:
           case LTC_ASN1_OBJECT_IDENTIFIER:
           case LTC_ASN1_IA5_STRING:
           case LTC_ASN1_PRINTABLE_STRING:
           case LTC_ASN1_UTF8_STRING:
           case LTC_ASN1_UTCTIME:
           case LTC_ASN1_SEQUENCE:
           case LTC_ASN1_SET:
           case LTC_ASN1_SETOF:
           case LTC_ASN1_CHOICE:
           case LTC_ASN1_RAW_BIT_STRING:
           case LTC_ASN1_TELETEX_STRING:
           case LTC_ASN1_GENERALIZEDTIME:
                LTC_SET_ASN1(list, x++, type, data, size);
                break;
           /* coverity[dead_error_line] */
           case LTC_ASN1_EOL:
           case LTC_ASN1_CUSTOM_TYPE:
                break;
       }
   }

   err = der_decode_sequence_ex(in, inlen, list, x, flags);
   XFREE(list);
   return err;
}

/**
  Decode a SEQUENCE type using a VA list
  @param in    Input buffer
  @param inlen Length of input in octets
  @remark <...> is of the form <type, size, data> (int, unsigned long, void*)
  @return CRYPT_OK on success
*/
int der_decode_sequence_multi(const unsigned char *in, unsigned long inlen, ...)
{
   va_list       a1, a2;
   int err;

   LTC_ARGCHK(in    != NULL);

   va_start(a1, inlen);
   va_start(a2, inlen);

   err = _der_decode_sequence_va(in, inlen, a1, a2, LTC_DER_SEQ_SEQUENCE | LTC_DER_SEQ_RELAXED);

   va_end(a2);
   va_end(a1);

   return err;
}

/**
  Decode a SEQUENCE type using a VA list
  @param in    Input buffer
  @param inlen Length of input in octets
  @param flags c.f. enum ltc_der_seq
  @remark <...> is of the form <type, size, data> (int, unsigned long, void*)
  @return CRYPT_OK on success
*/
int der_decode_sequence_multi_ex(const unsigned char *in, unsigned long inlen, unsigned int flags, ...)
{
   va_list       a1, a2;
   int err;

   LTC_ARGCHK(in    != NULL);

   va_start(a1, flags);
   va_start(a2, flags);

   err = _der_decode_sequence_va(in, inlen, a1, a2, flags);

   va_end(a2);
   va_end(a1);

   return err;
}

#endif


/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
