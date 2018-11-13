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
   @file ssh_decode_sequence_multi.c
   SSH data type representation as per RFC4251, Russ Williams
*/

#ifdef LTC_SSH

/**
  Decode a SSH sequence using a VA list
  @param in     Data to decode
  @param inlen  Length of buffer to decode
  @remark <...> is of the form <type, data> (int, void*) except for string <type, data, size>
  @return CRYPT_OK on success
*/
int ssh_decode_sequence_multi(const unsigned char *in, unsigned long inlen, ...)
{
   int           err;
   va_list       args;
   ssh_data_type type;
   void          *vdata;
   unsigned char *cdata;
   char          *sdata;
   ulong32       *u32data;
   ulong64       *u64data;
   unsigned long size, bufsize;

   LTC_ARGCHK(in    != NULL);

   /* Decode values from buffer */
   va_start(args, inlen);
   while ((type = (ssh_data_type)va_arg(args, int)) != LTC_SSHDATA_EOL) {
      /* Size of length field */
      if (type == LTC_SSHDATA_STRING ||
          type == LTC_SSHDATA_NAMELIST ||
          type == LTC_SSHDATA_MPINT)
      {
         /* Check we'll not read too far */
         if (inlen < 4) {
            err = CRYPT_BUFFER_OVERFLOW;
            goto error;
         }
      }

      /* Calculate (or read) length of data */
      size = (unsigned long)-1;
      switch (type) {
         case LTC_SSHDATA_BYTE:
         case LTC_SSHDATA_BOOLEAN:
            size = 1;
            break;
         case LTC_SSHDATA_UINT32:
            size = 4;
            break;
         case LTC_SSHDATA_UINT64:
            size = 8;
            break;
         case LTC_SSHDATA_STRING:
         case LTC_SSHDATA_NAMELIST:
         case LTC_SSHDATA_MPINT:
            LOAD32H(size, in);
            in += 4;
            inlen -= 4;
            break;

         case LTC_SSHDATA_EOL:
            /* Should never get here */
            err = CRYPT_INVALID_ARG;
            goto error;
      }

      /* Check we'll not read too far */
      if (inlen < size) {
         err = CRYPT_BUFFER_OVERFLOW;
         goto error;
      } else {
         inlen -= size;
      }

      /* Read data */
      switch (type) {
         case LTC_SSHDATA_BYTE:
            cdata = va_arg(args, unsigned char*);
            *cdata = *in++;
            break;
         case LTC_SSHDATA_BOOLEAN:
            cdata = va_arg(args, unsigned char*);
            /*
               The value 0 represents FALSE, and the value 1 represents TRUE.  All non-zero values MUST be
               interpreted as TRUE; however, applications MUST NOT store values other than 0 and 1.
            */
            *cdata = (*in++)?1:0;
            break;
         case LTC_SSHDATA_UINT32:
            u32data = va_arg(args, ulong32*);
            LOAD32H(*u32data, in);
            in += 4;
            break;
         case LTC_SSHDATA_UINT64:
            u64data = va_arg(args, ulong64*);
            LOAD64H(*u64data, in);
            in += 8;
            break;
         case LTC_SSHDATA_STRING:
         case LTC_SSHDATA_NAMELIST:
            sdata = va_arg(args, char*);
            bufsize = va_arg(args, unsigned long);
            if (size >= bufsize) {
               err = CRYPT_BUFFER_OVERFLOW;
               goto error;
            }
            if (size > 0) {
               XSTRNCPY(sdata, (const char *)in, size);
               sdata[size] = '\0'; /* strncpy doesn't NUL-terminate */
            } else {
               *sdata = '\0';
            }
            in += size;
            break;
         case LTC_SSHDATA_MPINT:
            vdata = va_arg(args, void*);
            if (size == 0) {
               if ((err = mp_set(vdata, 0)) != CRYPT_OK)                                                { goto error; }
            } else if ((in[0] & 0x80) != 0) {
               /* Negative number - not supported */
               err = CRYPT_INVALID_PACKET;
               goto error;
            } else {
               if ((err = mp_read_unsigned_bin(vdata, (unsigned char *)in, size)) != CRYPT_OK)          { goto error; }
            }
            in += size;
            break;

         case LTC_SSHDATA_EOL:
            /* Should never get here */
            err = CRYPT_INVALID_ARG;
            goto error;
      }
   }
   err = CRYPT_OK;

error:
   va_end(args);
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
