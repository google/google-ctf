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
  @file der_decode_custom_type.c
  ASN.1 DER, decode a Custom type, Steffen Jaeckel
*/

#ifdef LTC_DER

/**
   Decode a Custom type
   @param in       The DER encoded input
   @param inlen    The size of the input
   @param root     The item that defines the custom type to decode
   @return CRYPT_OK on success
*/
int der_decode_custom_type(const unsigned char *in, unsigned long  inlen,
                           ltc_asn1_list *root)
{
   LTC_ARGCHK(root != NULL);
   return der_decode_custom_type_ex(in, inlen, root, NULL, 0, LTC_DER_SEQ_ORDERED | LTC_DER_SEQ_RELAXED);
}

/**
   Extended-decode a Custom type

      This function is used to decode custom types and sequences/sets
      For custom types root is used
      For sequences/sets list and outlen are used

   @param in       The DER encoded input
   @param inlen    The size of the input
   @param root     The item that defines the custom type to decode
   @param list     The list of items to decode
   @param outlen   The number of items in the list
   @param flags    c.f. enum ltc_der_seq
   @return CRYPT_OK on success
*/
int der_decode_custom_type_ex(const unsigned char *in,   unsigned long  inlen,
                                    ltc_asn1_list *root,
                                    ltc_asn1_list *list, unsigned long  outlen,
                                    unsigned int   flags)
{
   int           err, seq_err, i, ordered;
   ltc_asn1_type type;
   ltc_asn1_list ident;
   unsigned long size, x, y, z, blksize;
   unsigned char* in_new = NULL;
   void          *data;

   LTC_ARGCHK(in   != NULL);

   /* get blk size */
   if (inlen < 2) {
      return CRYPT_INVALID_PACKET;
   }
   x = 0;

   if (root == NULL) {
      LTC_ARGCHK(list != NULL);

      /* sequence type? We allow 0x30 SEQUENCE and 0x31 SET since fundamentally they're the same structure */
      if (in[x] != 0x30 && in[x] != 0x31) {
         return CRYPT_INVALID_PACKET;
      }
      ++x;
   } else {
      if (root->type != LTC_ASN1_CUSTOM_TYPE) {
         return CRYPT_INVALID_PACKET;
      }

      /* Alloc a copy of the data for primitive handling. */
      if (root->pc == LTC_ASN1_PC_PRIMITIVE) {
         in_new = XMALLOC(inlen);
         if (in_new == NULL) {
            return CRYPT_MEM;
         }
         XMEMCPY(in_new, in, inlen);
         in = in_new;
      }

      y = inlen;
      if ((err = der_decode_asn1_identifier(in, &y, &ident)) != CRYPT_OK) {
         goto LBL_ERR;
      }
      if ((ident.type != root->type) ||
            (ident.klass != root->klass) ||
            (ident.pc != root->pc) ||
            (ident.tag != root->tag)) {
         err = CRYPT_INVALID_PACKET;
         goto LBL_ERR;
      }
      x += y;

      list = root->data;
      outlen = root->size;
   }

   if (root != NULL && root->pc == LTC_ASN1_PC_PRIMITIVE) {
      if (((unsigned long)root->used >= der_asn1_type_to_identifier_map_sz) ||
            (der_asn1_type_to_identifier_map[root->used] == -1)) {
         err = CRYPT_INVALID_PACKET;
         goto LBL_ERR;
      }

      root->type = (ltc_asn1_type)root->used;
      list = root;
      outlen = 1;

      x -= 1;
      in_new[x] = (unsigned char)der_asn1_type_to_identifier_map[list[0].type];
      blksize = inlen - x;
   } else {

      y = inlen - x;
      if ((err = der_decode_asn1_length(&in[x], &y, &blksize)) != CRYPT_OK) {
         goto LBL_ERR;
      }
      x += y;
   }

   /* would this blksize overflow? */
   if (blksize > (inlen - x)) {
      err = CRYPT_INVALID_PACKET;
      goto LBL_ERR;
   }

   /* mark all as unused */
   for (i = 0; i < (int)outlen; i++) {
       list[i].used = 0;
   }
   ordered = flags & LTC_DER_SEQ_ORDERED;

   /* ok read data */
   seq_err  = CRYPT_OK;
   blksize += x;
   inlen   -= x;
   for (i = 0; i < (int)outlen; i++) {
       z    = 0;
       type = list[i].type;
       size = list[i].size;
       data = list[i].data;
       if (!ordered && list[i].used == 1) { continue; }

       if (type == LTC_ASN1_EOL) {
          break;
       }

       if (root != NULL && root->pc == LTC_ASN1_PC_PRIMITIVE && i != 0) {
          err = CRYPT_PK_ASN1_ERROR;
          goto LBL_ERR;
       }

       switch (type) {
           case LTC_ASN1_BOOLEAN:
               z = inlen;
               if ((err = der_decode_boolean(in + x, z, ((int *)data))) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_boolean(&z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_INTEGER:
               z = inlen;
               if ((err = der_decode_integer(in + x, z, data)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_integer(data, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SHORT_INTEGER:
               z = inlen;
               if ((err = der_decode_short_integer(in + x, z, data)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_short_integer(((unsigned long*)data)[0], &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }

               break;

           case LTC_ASN1_BIT_STRING:
               z = inlen;
               if ((err = der_decode_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_RAW_BIT_STRING:
               z = inlen;
               if ((err = der_decode_raw_bit_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_bit_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_OCTET_STRING:
               z = inlen;
               if ((err = der_decode_octet_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_octet_string(size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_NULL:
               if (inlen < 2 || in[x] != 0x05 || in[x+1] != 0x00) {
                  if (!ordered || list[i].optional) { continue; }
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }
               z = 2;
               break;

           case LTC_ASN1_OBJECT_IDENTIFIER:
               z = inlen;
               if ((err = der_decode_object_identifier(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_object_identifier(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_TELETEX_STRING:
               z = inlen;
               if ((err = der_decode_teletex_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_teletex_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_IA5_STRING:
               z = inlen;
               if ((err = der_decode_ia5_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_ia5_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_PRINTABLE_STRING:
               z = inlen;
               if ((err = der_decode_printable_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_printable_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTF8_STRING:
               z = inlen;
               if ((err = der_decode_utf8_string(in + x, z, data, &size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               list[i].size = size;
               if ((err = der_length_utf8_string(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_UTCTIME:
               z = inlen;
               if ((err = der_decode_utctime(in + x, &z, data)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_GENERALIZEDTIME:
               z = inlen;
               if ((err = der_decode_generalizedtime(in + x, &z, data)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SET:
               z = inlen;
               if ((err = der_decode_set(in + x, z, data, size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_SETOF:
           case LTC_ASN1_SEQUENCE:
               /* detect if we have the right type */
               if ((type == LTC_ASN1_SETOF && (in[x] & 0x3F) != 0x31) || (type == LTC_ASN1_SEQUENCE && (in[x] & 0x3F) != 0x30)) {
                  err = CRYPT_INVALID_PACKET;
                  goto LBL_ERR;
               }

               z = inlen;
               err = der_decode_sequence_ex(in + x, z, data, size, flags);
               if (err == CRYPT_INPUT_TOO_LONG) {
                  seq_err = CRYPT_INPUT_TOO_LONG;
                  err = CRYPT_OK;
               }
               if (err != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_sequence(data, size, &z)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_CUSTOM_TYPE:
               z = inlen;
               err = der_decode_custom_type(in + x, z, &list[i]);
               if (err == CRYPT_INPUT_TOO_LONG) {
                  seq_err = CRYPT_INPUT_TOO_LONG;
                  err = CRYPT_OK;
               }
               if (err != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               if ((err = der_length_custom_type(&list[i], &z, NULL)) != CRYPT_OK) {
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_CHOICE:
               z = inlen;
               if ((err = der_decode_choice(in + x, &z, data, size)) != CRYPT_OK) {
                  if (!ordered || list[i].optional) { continue; }
                  goto LBL_ERR;
               }
               break;

           case LTC_ASN1_EOL:
               err = CRYPT_INVALID_ARG;
               goto LBL_ERR;
       }
       x           += z;
       inlen       -= z;
       list[i].used = 1;
       if (!ordered) {
          /* restart the decoder */
          i = -1;
       }
   }

   for (i = 0; i < (int)outlen; i++) {
      if (list[i].used == 0 && list[i].optional == 0) {
          err = CRYPT_INVALID_PACKET;
          goto LBL_ERR;
      }
   }

   if (blksize == x && seq_err == CRYPT_OK && inlen == 0) {
      /* everything decoded and no errors in nested sequences */
      err = CRYPT_OK;
   } else if (blksize == x && seq_err == CRYPT_INPUT_TOO_LONG && inlen == 0) {
      /* a sequence reported too-long input, but now we've decoded everything */
      err = CRYPT_OK;
   } else if (blksize != x && ((flags & LTC_DER_SEQ_STRICT) == LTC_DER_SEQ_STRICT)) {
      err = CRYPT_INVALID_PACKET;
   } else {
      err = CRYPT_INPUT_TOO_LONG;
   }

LBL_ERR:
   if (in_new != NULL) {
      XFREE(in_new);
   }
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
