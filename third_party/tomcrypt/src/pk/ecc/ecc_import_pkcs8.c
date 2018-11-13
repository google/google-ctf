/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_MECC

typedef struct {
   ltc_asn1_type t;
   ltc_asn1_list **pp;
} der_flexi_check;

#define LTC_SET_DER_FLEXI_CHECK(list, index, Type, P)    \
   do {                                         \
      int LTC_SDFC_temp##__LINE__ = (index);   \
      list[LTC_SDFC_temp##__LINE__].t = Type;  \
      list[LTC_SDFC_temp##__LINE__].pp = P;    \
   } while (0)

static int _der_flexi_sequence_cmp(const ltc_asn1_list *flexi, der_flexi_check *check)
{
   const ltc_asn1_list *cur;
   if (flexi->type != LTC_ASN1_SEQUENCE) {
      return CRYPT_INVALID_PACKET;
   }
   cur = flexi->child;
   while(check->t != LTC_ASN1_EOL) {
      if (!LTC_ASN1_IS_TYPE(cur, check->t)) {
         return CRYPT_INVALID_PACKET;
      }
      if (check->pp != NULL) *check->pp = (ltc_asn1_list*)cur;
      cur = cur->next;
      check++;
   }
   return CRYPT_OK;
}

/* NOTE: _der_decode_pkcs8_flexi & related stuff can be shared with rsa_import_pkcs8() */

int ecc_import_pkcs8(const unsigned char *in, unsigned long inlen,
                     const void *pwd, unsigned long pwdlen,
                     ecc_key *key)
{
   void          *a, *b, *gx, *gy;
   unsigned long len, cofactor, n;
   const char    *pka_ec_oid;
   int           err;
   char          OID[256];
   const ltc_ecc_curve *curve;
   ltc_asn1_list *p = NULL, *l = NULL;
   der_flexi_check flexi_should[7];
   ltc_asn1_list *seq, *priv_key;

   LTC_ARGCHK(in          != NULL);
   LTC_ARGCHK(key         != NULL);
   LTC_ARGCHK(ltc_mp.name != NULL);

   /* get EC alg oid */
   err = pk_get_oid(PKA_EC, &pka_ec_oid);
   if (err != CRYPT_OK) return err;

   /* init key */
   err = mp_init_multi(&a, &b, &gx, &gy, NULL);
   if (err != CRYPT_OK) return err;


   if ((err = pkcs8_decode_flexi(in, inlen, pwd, pwdlen, &l)) == CRYPT_OK) {

      /* Setup for basic structure */
      n=0;
      LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, NULL);
      LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &seq);
      LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OCTET_STRING, &priv_key);
      LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);

      if (((err = _der_flexi_sequence_cmp(l, flexi_should)) == CRYPT_OK) &&
            (pk_oid_cmp_with_asn1(pka_ec_oid, seq->child) == CRYPT_OK)) {
         ltc_asn1_list *version, *field, *point, *point_g, *order, *p_cofactor;

         /* Setup for CASE 2 */
         n=0;
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, &version);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &field);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_SEQUENCE, &point);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_OCTET_STRING, &point_g);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, &order);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n++, LTC_ASN1_INTEGER, &p_cofactor);
         LTC_SET_DER_FLEXI_CHECK(flexi_should, n, LTC_ASN1_EOL, NULL);

         if (LTC_ASN1_IS_TYPE(seq->child->next, LTC_ASN1_OBJECT_IDENTIFIER)) {
            /* CASE 1: curve by OID (AKA short variant):
             *   0:d=0  hl=2 l= 100 cons: SEQUENCE
             *   2:d=1  hl=2 l=   1 prim:   INTEGER        :00
             *   5:d=1  hl=2 l=  16 cons:   SEQUENCE       (== *seq)
             *   7:d=2  hl=2 l=   7 prim:     OBJECT       :id-ecPublicKey
             *  16:d=2  hl=2 l=   5 prim:     OBJECT       :(== *curve_oid (e.g. secp256k1 (== 1.3.132.0.10)))
             *  23:d=1  hl=2 l=  77 prim:   OCTET STRING   :bytes (== *priv_key)
             */
            ltc_asn1_list *curve_oid = seq->child->next;
            len = sizeof(OID);
            if ((err = pk_oid_num_to_str(curve_oid->data, curve_oid->size, OID, &len)) != CRYPT_OK) { goto LBL_DONE; }
            if ((err = ecc_find_curve(OID, &curve)) != CRYPT_OK)                          { goto LBL_DONE; }
            if ((err = ecc_set_curve(curve, key)) != CRYPT_OK)                            { goto LBL_DONE; }
         }
         else if ((err = _der_flexi_sequence_cmp(seq->child->next, flexi_should)) == CRYPT_OK) {
            /* CASE 2: explicit curve parameters (AKA long variant):
             *   0:d=0  hl=3 l= 227 cons: SEQUENCE
             *   3:d=1  hl=2 l=   1 prim:   INTEGER              :00
             *   6:d=1  hl=3 l= 142 cons:   SEQUENCE             (== *seq)
             *   9:d=2  hl=2 l=   7 prim:     OBJECT             :id-ecPublicKey
             *  18:d=2  hl=3 l= 130 cons:     SEQUENCE
             *  21:d=3  hl=2 l=   1 prim:       INTEGER          :01
             *  24:d=3  hl=2 l=  44 cons:       SEQUENCE         (== *field)
             *  26:d=4  hl=2 l=   7 prim:         OBJECT         :prime-field
             *  35:d=4  hl=2 l=  33 prim:         INTEGER        :(== *prime / curve.prime)
             *  70:d=3  hl=2 l=   6 cons:       SEQUENCE         (== *point)
             *  72:d=4  hl=2 l=   1 prim:         OCTET STRING   :bytes (== curve.A)
             *  75:d=4  hl=2 l=   1 prim:         OCTET STRING   :bytes (== curve.B)
             *  78:d=3  hl=2 l=  33 prim:       OCTET STRING     :bytes (== *g_point / curve.G-point)
             * 113:d=3  hl=2 l=  33 prim:       INTEGER          :(== *order / curve.order)
             * 148:d=3  hl=2 l=   1 prim:       INTEGER          :(== curve.cofactor)
             * 151:d=1  hl=2 l=  77 prim:   OCTET STRING         :bytes (== *priv_key)
             */

            if (mp_get_int(version->data) != 1) {
               goto LBL_DONE;
            }
            cofactor = mp_get_int(p_cofactor->data);

            if (LTC_ASN1_IS_TYPE(field->child, LTC_ASN1_OBJECT_IDENTIFIER) &&
                LTC_ASN1_IS_TYPE(field->child->next, LTC_ASN1_INTEGER) &&
                LTC_ASN1_IS_TYPE(point->child, LTC_ASN1_OCTET_STRING) &&
                LTC_ASN1_IS_TYPE(point->child->next, LTC_ASN1_OCTET_STRING)) {

               ltc_asn1_list *prime = field->child->next;
               if ((err = mp_read_unsigned_bin(a, point->child->data, point->child->size)) != CRYPT_OK) {
                  goto LBL_DONE;
               }
               if ((err = mp_read_unsigned_bin(b, point->child->next->data, point->child->next->size)) != CRYPT_OK) {
                  goto LBL_DONE;
               }
               if ((err = ltc_ecc_import_point(point_g->data, point_g->size, prime->data, a, b, gx, gy)) != CRYPT_OK) {
                  goto LBL_DONE;
               }
               if ((err = ecc_set_curve_from_mpis(a, b, prime->data, order->data, gx, gy, cofactor, key)) != CRYPT_OK) {
                  goto LBL_DONE;
               }
            }
         }
         else {
            err = CRYPT_INVALID_PACKET;
            goto LBL_DONE;
         }

         /* load private key value 'k' */
         len = priv_key->size;
         if ((err = der_decode_sequence_flexi(priv_key->data, &len, &p)) == CRYPT_OK) {
            if (p->type == LTC_ASN1_SEQUENCE &&
                LTC_ASN1_IS_TYPE(p->child, LTC_ASN1_INTEGER) &&
                LTC_ASN1_IS_TYPE(p->child->next, LTC_ASN1_OCTET_STRING)) {
               ltc_asn1_list *lk = p->child->next;
               if (mp_cmp_d(p->child->data, 1) != LTC_MP_EQ) {
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ECCFREE;
               }
               if ((err = ecc_set_key(lk->data, lk->size, PK_PRIVATE, key)) != CRYPT_OK) {
                  goto LBL_ECCFREE;
               }
               goto LBL_DONE; /* success */
            }
         }
      }
   }
   err = CRYPT_INVALID_PACKET;
   goto LBL_DONE;

LBL_ECCFREE:
   ecc_free(key);
LBL_DONE:
   mp_clear_multi(a, b, gx, gy, NULL);
   if (l) der_free_sequence_flexi(l);
   if (p) der_free_sequence_flexi(p);
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
