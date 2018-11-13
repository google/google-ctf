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

int ltc_ecc_export_point(unsigned char *out, unsigned long *outlen, void *x, void *y, unsigned long size, int compressed)
{
   int err;
   unsigned char buf[ECC_BUF_SIZE];
   unsigned long xsize, ysize;

   if (size > sizeof(buf)) return CRYPT_BUFFER_OVERFLOW;
   if ((xsize = mp_unsigned_bin_size(x)) > size) return CRYPT_BUFFER_OVERFLOW;
   if ((ysize = mp_unsigned_bin_size(y)) > size) return CRYPT_BUFFER_OVERFLOW;

   if(compressed) {
      if (*outlen < (1 + size)) {
         *outlen = 1 + size;
         return CRYPT_BUFFER_OVERFLOW;
      }
      /* store first byte */
      out[0] = mp_isodd(y) ? 0x03 : 0x02;
      /* pad and store x */
      zeromem(buf, sizeof(buf));
      if ((err = mp_to_unsigned_bin(x, buf + (size - xsize))) != CRYPT_OK) return err;
      XMEMCPY(out+1, buf, size);
      /* adjust outlen */
      *outlen = 1 + size;
   }
   else {
      if (*outlen < (1 + 2*size)) {
         *outlen = 1 + 2*size;
         return CRYPT_BUFFER_OVERFLOW;
      }
      /* store byte 0x04 */
      out[0] = 0x04;
      /* pad and store x */
      zeromem(buf, sizeof(buf));
      if ((err = mp_to_unsigned_bin(x, buf + (size - xsize))) != CRYPT_OK) return err;
      XMEMCPY(out+1, buf, size);
      /* pad and store y */
      zeromem(buf, sizeof(buf));
      if ((err = mp_to_unsigned_bin(y, buf + (size - ysize))) != CRYPT_OK) return err;
      XMEMCPY(out+1+size, buf, size);
      /* adjust outlen */
      *outlen = 1 + 2*size;
   }
   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
