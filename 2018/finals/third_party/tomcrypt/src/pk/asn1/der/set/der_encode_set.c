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
  @file der_encode_set.c
  ASN.1 DER, Encode a SET, Tom St Denis
*/

#ifdef LTC_DER

/* LTC define to ASN.1 TAG */
static int _ltc_to_asn1(ltc_asn1_type v)
{
   return der_asn1_type_to_identifier_map[v];
}


static int _qsort_helper(const void *a, const void *b)
{
   ltc_asn1_list *A = (ltc_asn1_list *)a, *B = (ltc_asn1_list *)b;
   int            r;

   r = _ltc_to_asn1(A->type) - _ltc_to_asn1(B->type);

   /* for QSORT the order is UNDEFINED if they are "equal" which means it is NOT DETERMINISTIC.  So we force it to be :-) */
   if (r == 0) {
      /* their order in the original list now determines the position */
      return A->used - B->used;
   }
   return r;
}

/*
   Encode a SET type
   @param list      The list of items to encode
   @param inlen     The number of items in the list
   @param out       [out] The destination
   @param outlen    [in/out] The size of the output
   @return CRYPT_OK on success
*/
int der_encode_set(const ltc_asn1_list *list, unsigned long inlen,
                   unsigned char *out,        unsigned long *outlen)
{
   ltc_asn1_list  *copy;
   unsigned long   x;
   int             err;

   /* make copy of list */
   copy = XCALLOC(inlen, sizeof(*copy));
   if (copy == NULL) {
      return CRYPT_MEM;
   }

   /* fill in used member with index so we can fully sort it */
   for (x = 0; x < inlen; x++) {
       copy[x]      = list[x];
       copy[x].used = x;
   }

   /* sort it by the "type" field */
   XQSORT(copy, inlen, sizeof(*copy), &_qsort_helper);

   /* call der_encode_sequence_ex() */
   err = der_encode_sequence_ex(copy, inlen, out, outlen, LTC_ASN1_SET);

   /* free list */
   XFREE(copy);

   return err;
}


#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
