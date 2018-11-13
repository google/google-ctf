/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_PADDING

/**
   Remove padding from your data

      This depads your data.

   @param data     The data to depad
   @param length   [in/out] The size of the data before/after (removing padding)
   @param mode     One of the LTC_PAD_xx flags
   @return CRYPT_OK on success
*/
int padding_depad(const unsigned char *data, unsigned long *length, unsigned long mode)
{
   unsigned long padded_length, unpadded_length, n;
   unsigned char pad;
   enum padding_type type;

   LTC_ARGCHK(data   != NULL);
   LTC_ARGCHK(length != NULL);

   padded_length = *length;

   type = mode & LTC_PAD_MASK;

   if (type < LTC_PAD_ONE_AND_ZERO) {
      pad = data[padded_length - 1];

      if (pad > padded_length) return CRYPT_INVALID_ARG;

      unpadded_length = padded_length - pad;
   } else {
      /* init pad to calm old compilers */
      pad = 0x0;
      unpadded_length = padded_length;
   }

   switch (type) {
      case LTC_PAD_ANSI_X923:
         pad = 0x0;
         /* FALLTHROUGH */
      case LTC_PAD_PKCS7:
         for (n = unpadded_length; n < padded_length - 1; ++n) {
            if (data[n] != pad) return CRYPT_INVALID_PACKET;
         }
         break;
#ifdef LTC_RNG_GET_BYTES
      case LTC_PAD_ISO_10126:
         /* nop */
         break;
#endif
      case LTC_PAD_ONE_AND_ZERO:
         while (unpadded_length > 0 && data[unpadded_length - 1] != 0x80) {
            if (data[unpadded_length - 1] != 0x0) return CRYPT_INVALID_PACKET;
            unpadded_length--;
         }
         if (unpadded_length == 0) return CRYPT_INVALID_PACKET;
         unpadded_length--;
         if (data[unpadded_length] != 0x80) return CRYPT_INVALID_PACKET;
         break;
      case LTC_PAD_ZERO:
      case LTC_PAD_ZERO_ALWAYS:
         while (unpadded_length > 0 && data[unpadded_length - 1] == 0x0) {
            unpadded_length--;
         }
         if (type == LTC_PAD_ZERO_ALWAYS) {
            if (unpadded_length == padded_length) return CRYPT_INVALID_PACKET;
            if (data[unpadded_length] != 0x0) return CRYPT_INVALID_PACKET;
         }
         break;
      default:
         return CRYPT_INVALID_ARG;
   }

   *length = unpadded_length;

   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
