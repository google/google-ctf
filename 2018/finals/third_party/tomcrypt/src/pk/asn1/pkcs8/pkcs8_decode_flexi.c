/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_PKCS_8

/**
   PKCS#8 decrypt if necessary & flexi-decode

   @param in            Pointer to the ASN.1 encoded input data
   @param inlen         Length of the input data
   @param pwd           Pointer to the password that was used when encrypting
   @param pwdlen        Length of the password
   @param decoded_list  Pointer to a pointer for the flexi-decoded list
   @return CRYPT_OK on success
*/
int pkcs8_decode_flexi(const unsigned char  *in,  unsigned long inlen,
                                const void  *pwd, unsigned long pwdlen,
                             ltc_asn1_list **decoded_list)
{
   unsigned long len = inlen;
   unsigned long dec_size;
   unsigned char *dec_data = NULL;
   ltc_asn1_list *l = NULL;
   int err;

   LTC_ARGCHK(in           != NULL);
   LTC_ARGCHK(decoded_list != NULL);

   *decoded_list = NULL;
   if ((err = der_decode_sequence_flexi(in, &len, &l)) == CRYPT_OK) {
      /* the following "if" detects whether it is encrypted or not */
      /* PKCS8 Setup
       *  0:d=0  hl=4 l= 380 cons: SEQUENCE
       *  4:d=1  hl=2 l=  78 cons:   SEQUENCE
       *  6:d=2  hl=2 l=   9 prim:     OBJECT             :OID indicating PBES1 or PBES2 (== *lalgoid)
       * 17:d=2  hl=2 l=  65 cons:     SEQUENCE
       *     Stuff in between is dependent on whether it's PBES1 or PBES2
       * 84:d=1  hl=4 l= 296 prim:   OCTET STRING         :bytes (== encrypted data)
       */
      if (l->type == LTC_ASN1_SEQUENCE &&
          LTC_ASN1_IS_TYPE(l->child, LTC_ASN1_SEQUENCE) &&
          LTC_ASN1_IS_TYPE(l->child->child, LTC_ASN1_OBJECT_IDENTIFIER) &&
          LTC_ASN1_IS_TYPE(l->child->child->next, LTC_ASN1_SEQUENCE) &&
          LTC_ASN1_IS_TYPE(l->child->next, LTC_ASN1_OCTET_STRING)) {
         ltc_asn1_list *lalgoid = l->child->child;
         pbes_arg pbes;

         XMEMSET(&pbes, 0, sizeof(pbes));

         if (pbes1_extract(lalgoid, &pbes) == CRYPT_OK) {
            /* Successfully extracted PBES1 parameters */
         } else if (pbes2_extract(lalgoid, &pbes) == CRYPT_OK) {
            /* Successfully extracted PBES2 parameters */
         } else {
            /* unsupported encryption */
            err = CRYPT_INVALID_PACKET;
            goto LBL_DONE;
         }

         pbes.enc_data = l->child->next;
         pbes.pwd = pwd;
         pbes.pwdlen = pwdlen;

         dec_size = pbes.enc_data->size;
         if ((dec_data = XMALLOC(dec_size)) == NULL) {
            err = CRYPT_MEM;
            goto LBL_DONE;
         }

         if ((err = pbes_decrypt(&pbes, dec_data, &dec_size)) != CRYPT_OK) goto LBL_DONE;

         der_free_sequence_flexi(l);
         l = NULL;
         err = der_decode_sequence_flexi(dec_data, &dec_size, &l);
         if (err != CRYPT_OK) goto LBL_DONE;
         *decoded_list = l;
      }
      else {
         /* not encrypted */
         err = CRYPT_OK;
         *decoded_list = l;
      }
      /* Set l to NULL so it won't be free'd */
      l = NULL;
   }

LBL_DONE:
   if (l) der_free_sequence_flexi(l);
   if (dec_data) {
      zeromem(dec_data, dec_size);
      XFREE(dec_data);
   }
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
