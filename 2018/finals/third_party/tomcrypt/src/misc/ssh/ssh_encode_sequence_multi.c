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
   @file ssh_encode_sequence_multi.c
   SSH data type representation as per RFC4251, Russ Williams
*/

#ifdef LTC_SSH

/**
  Encode a SSH sequence using a VA list
  @param out    [out] Destination for data
  @param outlen [in/out] Length of buffer and resulting length of output
  @remark <...> is of the form <type, data> (int, void*)
  @return CRYPT_OK on success
*/
int ssh_encode_sequence_multi(unsigned char *out, unsigned long *outlen, ...)
{
   int           err;
   va_list       args;
   unsigned long size;
   ssh_data_type type;
   void         *vdata;
   const char   *sdata;
   int           idata;
   ulong32       u32data;
   ulong64       u64data;

   LTC_ARGCHK(out    != NULL);
   LTC_ARGCHK(outlen != NULL);

   /* Check values and calculate output size */
   size = 0;
   va_start(args, outlen);
   while ((type = (ssh_data_type)va_arg(args, int)) != LTC_SSHDATA_EOL) {
      switch (type) {
         case LTC_SSHDATA_BYTE:
         case LTC_SSHDATA_BOOLEAN: /* Both stored as 1 byte */
            LTC_UNUSED_PARAM( va_arg(args, int) );
            size++;
            break;
         case LTC_SSHDATA_UINT32:
            LTC_UNUSED_PARAM( va_arg(args, ulong32) );
            size += 4;
            break;
         case LTC_SSHDATA_UINT64:
            LTC_UNUSED_PARAM( va_arg(args, ulong64) );
            size += 8;
            break;
         case LTC_SSHDATA_STRING:
         case LTC_SSHDATA_NAMELIST:
            sdata = va_arg(args, char*);
            size += 4;
            size += strlen(sdata);
            break;
         case LTC_SSHDATA_MPINT:
            vdata = va_arg(args, void*);
            /* Calculate size */
            size += 4;
            if (mp_iszero(vdata) != LTC_MP_YES) {
               size += mp_unsigned_bin_size(vdata);
               if ((mp_count_bits(vdata) & 7) == 0) size++; /* Zero padding if high bit set */
            }
            break;

         case LTC_SSHDATA_EOL: /* Should never get here */
            err = CRYPT_INVALID_ARG;
            goto error;
      }
   }
   va_end(args);

   /* Check we have sufficient space */
   if (*outlen < size) {
      *outlen = size;
      err = CRYPT_BUFFER_OVERFLOW;
      goto errornoargs;
   }
   *outlen = size;

   /* Encode values into buffer */
   va_start(args, outlen);
   while ((type = (ssh_data_type)va_arg(args, int)) != LTC_SSHDATA_EOL) {
      switch (type) {
         case LTC_SSHDATA_BYTE:
            idata = va_arg(args, int);

            *out++ = (unsigned char)(idata & 255);
            break;
         case LTC_SSHDATA_BOOLEAN:
            idata = va_arg(args, int);

            /*
               The value 0 represents FALSE, and the value 1 represents TRUE.  All non-zero values MUST be
               interpreted as TRUE; however, applications MUST NOT store values other than 0 and 1.
            */
            *out++ = (idata)?1:0;
            break;
         case LTC_SSHDATA_UINT32:
            u32data = va_arg(args, ulong32);
            STORE32H(u32data, out);
            out += 4;
            break;
         case LTC_SSHDATA_UINT64:
            u64data = va_arg(args, ulong64);
            STORE64H(u64data, out);
            out += 8;
            break;
         case LTC_SSHDATA_STRING:
         case LTC_SSHDATA_NAMELIST:
            sdata = va_arg(args, char*);
            size = strlen(sdata);
            STORE32H(size, out);
            out += 4;
            XSTRNCPY((char *)out, sdata, size);
            out += size;
            break;
         case LTC_SSHDATA_MPINT:
            vdata = va_arg(args, void*);
            if (mp_iszero(vdata) == LTC_MP_YES) {
               STORE32H(0, out);
               out += 4;
            } else {
               size = mp_unsigned_bin_size(vdata);
               if ((mp_count_bits(vdata) & 7) == 0) {
                  /* Zero padding if high bit set */
                  STORE32H(size+1, out);
                  out += 4;
                  *out++ = 0;
               } else {
                  STORE32H(size, out);
                  out += 4;
               }
               if ((err = mp_to_unsigned_bin(vdata, out)) != CRYPT_OK) {
                  err = CRYPT_ERROR;
                  goto error;
               }
               out += size;
            }
            break;

         case LTC_SSHDATA_EOL: /* Should never get here */
            err = CRYPT_INVALID_ARG;
            goto error;
      }
   }
   err = CRYPT_OK;

error:
   va_end(args);
errornoargs:
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
