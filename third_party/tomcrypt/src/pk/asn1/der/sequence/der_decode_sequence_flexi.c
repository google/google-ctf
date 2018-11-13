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
  @file der_decode_sequence_flexi.c
  ASN.1 DER, decode an array of ASN.1 types with a flexi parser, Tom St Denis
*/

#ifdef LTC_DER

static int _new_element(ltc_asn1_list **l)
{
   /* alloc new link */
   if (*l == NULL) {
      *l = XCALLOC(1, sizeof(ltc_asn1_list));
      if (*l == NULL) {
         return CRYPT_MEM;
      }
   } else {
      (*l)->next = XCALLOC(1, sizeof(ltc_asn1_list));
      if ((*l)->next == NULL) {
         return CRYPT_MEM;
      }
      (*l)->next->prev = *l;
      *l = (*l)->next;
   }
   return CRYPT_OK;
}

/**
   ASN.1 DER Flexi(ble) decoder will decode arbitrary DER packets and create a linked list of the decoded elements.
   @param in      The input buffer
   @param inlen   [in/out] The length of the input buffer and on output the amount of decoded data
   @param out     [out] A pointer to the linked list
   @return CRYPT_OK on success.
*/
int der_decode_sequence_flexi(const unsigned char *in, unsigned long *inlen, ltc_asn1_list **out)
{
   ltc_asn1_list *l, *t;
   unsigned long err, identifier, len, totlen, data_offset, id_len, len_len;
   void          *realloc_tmp;

   LTC_ARGCHK(in    != NULL);
   LTC_ARGCHK(inlen != NULL);
   LTC_ARGCHK(out   != NULL);

   l = NULL;
   totlen = 0;

   if (*inlen == 0) {
      /* alloc new link */
      if ((err = _new_element(&l)) != CRYPT_OK) {
         goto error;
      }
   }

   /* scan the input and and get lengths and what not */
   while (*inlen) {
      /* alloc new link */
      if ((err = _new_element(&l)) != CRYPT_OK) {
         goto error;
      }

      id_len = *inlen;
      if ((err = der_decode_asn1_identifier(in, &id_len, l)) != CRYPT_OK) {
         goto error;
      }
      /* read the type byte */
      identifier = *in;

      if (l->type != LTC_ASN1_EOL) {
         /* fetch length */
         len_len = *inlen - id_len;
#if defined(LTC_TEST_DBG)
         data_offset = 666;
         len = 0;
#endif
         if ((err = der_decode_asn1_length(&in[id_len], &len_len, &len)) != CRYPT_OK) {
#if defined(LTC_TEST_DBG)
            fprintf(stderr, "E1 %02lx: hl=%4lu l=%4lu - %s (%s)\n", identifier, data_offset, len, der_asn1_tag_to_string_map[l->tag], error_to_string(err));
#endif
            goto error;
         } else if (len > (*inlen - id_len - len_len)) {
            err = CRYPT_INVALID_PACKET;
#if defined(LTC_TEST_DBG)
            fprintf(stderr, "E2 %02lx: hl=%4lu l=%4lu - %s (%s)\n", identifier, data_offset, len, der_asn1_tag_to_string_map[l->tag], error_to_string(err));
#endif
            goto error;
         }
         data_offset = id_len + len_len;
#if defined(LTC_TEST_DBG) && LTC_TEST_DBG > 1
         if (l->type == LTC_ASN1_CUSTOM_TYPE && l->klass == LTC_ASN1_CL_CONTEXT_SPECIFIC) {
            fprintf(stderr, "OK %02lx: hl=%4lu l=%4lu - Context Specific[%s %llu]\n", identifier, data_offset, len, der_asn1_pc_to_string_map[l->pc], l->tag);
         } else {
            fprintf(stderr, "OK %02lx: hl=%4lu l=%4lu - %s\n", identifier, data_offset, len, der_asn1_tag_to_string_map[l->tag]);
         }
#endif
         len += data_offset;

         if (l->type == LTC_ASN1_CUSTOM_TYPE) {
            /* Custom type, use the 'used' field to store the original identifier */
            l->used = identifier;
            if (l->pc == LTC_ASN1_PC_CONSTRUCTED) {
               /* treat constructed elements like SEQUENCEs */
               identifier = 0x20;
            } else {
               /* primitive elements are treated as opaque data */
               identifier = 0x80;
            }
         }
      } else {
         /* Init this so gcc won't complain,
          * as this case will only be hit when we
          * can't decode the identifier so the
          * switch-case should go to default anyway...
          */
         data_offset = 0;
         len = 0;
      }

     /* now switch on type */
      switch (identifier) {
         case 0x01: /* BOOLEAN */
            if (l->type != LTC_ASN1_BOOLEAN) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = 1;
            l->data = XCALLOC(1, sizeof(int));

            if ((err = der_decode_boolean(in, *inlen, l->data)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_boolean(&len)) != CRYPT_OK) {
               goto error;
            }
            break;

         case 0x02: /* INTEGER */
             if (l->type != LTC_ASN1_INTEGER) {
                err = CRYPT_PK_ASN1_ERROR;
                goto error;
             }

             /* init field */
             l->size = 1;
             if ((err = mp_init(&l->data)) != CRYPT_OK) {
                 goto error;
             }

             /* decode field */
             if ((err = der_decode_integer(in, *inlen, l->data)) != CRYPT_OK) {
                 goto error;
             }

             /* calc length of object */
             if ((err = der_length_integer(l->data, &len)) != CRYPT_OK) {
                 goto error;
             }
             break;

         case 0x03: /* BIT */
            if (l->type != LTC_ASN1_BIT_STRING) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = len * 8; /* *8 because we store decoded bits one per char and they are encoded 8 per char.  */

            if ((l->data = XCALLOC(1, l->size)) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            if ((err = der_decode_bit_string(in, *inlen, l->data, &l->size)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_bit_string(l->size, &len)) != CRYPT_OK) {
               goto error;
            }
            break;

         case 0x04: /* OCTET */
            if (l->type != LTC_ASN1_OCTET_STRING) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = len;

            if ((l->data = XCALLOC(1, l->size)) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            if ((err = der_decode_octet_string(in, *inlen, l->data, &l->size)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_octet_string(l->size, &len)) != CRYPT_OK) {
               goto error;
            }
            break;

         case 0x05: /* NULL */
            if (l->type != LTC_ASN1_NULL) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* valid NULL is 0x05 0x00 */
            if (in[0] != 0x05 || in[1] != 0x00) {
               err = CRYPT_INVALID_PACKET;
               goto error;
            }

            /* simple to store ;-) */
            l->data = NULL;
            l->size = 0;
            len     = 2;

            break;

         case 0x06: /* OID */
            if (l->type != LTC_ASN1_OBJECT_IDENTIFIER) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = len;

            if ((l->data = XCALLOC(len, sizeof(unsigned long))) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            if ((err = der_decode_object_identifier(in, *inlen, l->data, &l->size)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_object_identifier(l->data, l->size, &len)) != CRYPT_OK) {
               goto error;
            }

            /* resize it to save a bunch of mem */
            if ((realloc_tmp = XREALLOC(l->data, l->size * sizeof(unsigned long))) == NULL) {
               /* out of heap but this is not an error */
               break;
            }
            l->data = realloc_tmp;
            break;

         case 0x0C: /* UTF8 */

            /* init field */
            if (l->type != LTC_ASN1_UTF8_STRING) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }
            l->size = len;

            if ((l->data = XCALLOC(sizeof(wchar_t), l->size)) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            if ((err = der_decode_utf8_string(in, *inlen, l->data, &l->size)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_utf8_string(l->data, l->size, &len)) != CRYPT_OK) {
               goto error;
            }
            break;

         case 0x13: /* PRINTABLE */
            if (l->type != LTC_ASN1_PRINTABLE_STRING) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = len;

            if ((l->data = XCALLOC(1, l->size)) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            if ((err = der_decode_printable_string(in, *inlen, l->data, &l->size)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_printable_string(l->data, l->size, &len)) != CRYPT_OK) {
               goto error;
            }
            break;

         case 0x14: /* TELETEXT */
            if (l->type != LTC_ASN1_TELETEX_STRING) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = len;

            if ((l->data = XCALLOC(1, l->size)) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            if ((err = der_decode_teletex_string(in, *inlen, l->data, &l->size)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_teletex_string(l->data, l->size, &len)) != CRYPT_OK) {
               goto error;
            }
            break;

         case 0x16: /* IA5 */
            if (l->type != LTC_ASN1_IA5_STRING) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = len;

            if ((l->data = XCALLOC(1, l->size)) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            if ((err = der_decode_ia5_string(in, *inlen, l->data, &l->size)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_ia5_string(l->data, l->size, &len)) != CRYPT_OK) {
               goto error;
            }
            break;

         case 0x17: /* UTC TIME */
            if (l->type != LTC_ASN1_UTCTIME) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = 1;

            if ((l->data = XCALLOC(1, sizeof(ltc_utctime))) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            len = *inlen;
            if ((err = der_decode_utctime(in, &len, l->data)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_utctime(l->data, &len)) != CRYPT_OK) {
               goto error;
            }
            break;

         case 0x18:
            if (l->type != LTC_ASN1_GENERALIZEDTIME) {
               err = CRYPT_PK_ASN1_ERROR;
               goto error;
            }

            /* init field */
            l->size = len;

            if ((l->data = XCALLOC(1, sizeof(ltc_generalizedtime))) == NULL) {
               err = CRYPT_MEM;
               goto error;
            }

            if ((err = der_decode_generalizedtime(in, &len, l->data)) != CRYPT_OK) {
               goto error;
            }

            if ((err = der_length_generalizedtime(l->data, &len)) != CRYPT_OK) {
               goto error;
            }

            break;

         case 0x20: /* Any CONSTRUCTED element that is neither SEQUENCE nor SET */
         case 0x30: /* SEQUENCE */
         case 0x31: /* SET */

             /* init field */
             if (identifier == 0x20) {
               if (l->type != LTC_ASN1_CUSTOM_TYPE) {
                  err = CRYPT_PK_ASN1_ERROR;
                  goto error;
               }
             }
             else if (identifier == 0x30) {
               if (l->type != LTC_ASN1_SEQUENCE) {
                  err = CRYPT_PK_ASN1_ERROR;
                  goto error;
               }
             }
             else {
               if (l->type != LTC_ASN1_SET) {
                  err = CRYPT_PK_ASN1_ERROR;
                  goto error;
               }
             }

             if ((l->data = XMALLOC(len)) == NULL) {
                err = CRYPT_MEM;
                goto error;
             }

             XMEMCPY(l->data, in, len);
             l->size = len;


             /* jump to the start of the data */
             in     += data_offset;
             *inlen -= data_offset;
             len    -= data_offset;

             /* save the decoded ASN.1 len */
             len_len = len;

             /* Sequence elements go as child */
             if ((err = der_decode_sequence_flexi(in, &len, &(l->child))) != CRYPT_OK) {
                goto error;
             }
             if (len_len != len) {
                err = CRYPT_PK_ASN1_ERROR;
                goto error;
             }

             /* len update */
             totlen += data_offset;

             /* the flexi decoder can also do nothing, so make sure a child has been allocated */
             if (l->child) {
                /* link them up y0 */
                l->child->parent = l;
             }

             t = l;
             len_len = 0;
             while((t != NULL) && (t->child != NULL)) {
                len_len++;
                t = t->child;
             }
             if (len_len > LTC_DER_MAX_RECURSION) {
                err = CRYPT_PK_ASN1_ERROR;
                goto error;
             }

             break;

         case 0x80: /* Context-specific */
             if (l->type != LTC_ASN1_CUSTOM_TYPE) {
                err = CRYPT_PK_ASN1_ERROR;
                goto error;
             }

             if ((l->data = XCALLOC(1, len - data_offset)) == NULL) {
                err = CRYPT_MEM;
                goto error;
             }

             XMEMCPY(l->data, in + data_offset, len - data_offset);
             l->size = len - data_offset;

             break;

         default:
           /* invalid byte ... this is a soft error */
           /* remove link */
           if (l->prev) {
              l       = l->prev;
              XFREE(l->next);
              l->next = NULL;
           }
           goto outside;
      }

      /* advance pointers */
      totlen  += len;
      in      += len;
      *inlen  -= len;
   }

outside:

   /* in case we processed anything */
   if (totlen) {
      /* rewind l please */
      while (l->prev != NULL || l->parent != NULL) {
         if (l->parent != NULL) {
            l = l->parent;
         } else {
            l = l->prev;
         }
      }
   }

   /* return */
   *out   = l;
   *inlen = totlen;
   return CRYPT_OK;

error:
   /* free list */
   der_sequence_free(l);

   return err;
}

#endif


/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
