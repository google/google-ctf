/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

#ifdef LTC_PBES

/**
   Decrypt Data encrypted via either PBES1 or PBES2

   @param arg        The according PBES parameters
   @param dec_data   [out] The decrypted data
   @param dec_size   [in/out] The length of the encrypted resp. decrypted data
   @return CRYPT_OK on success
*/
int pbes_decrypt(const pbes_arg  *arg, unsigned char *dec_data, unsigned long *dec_size)
{
   int err, hid, cid;
   unsigned char k[32], *iv;
   unsigned long klen, keylen, dlen;
   long diff;
   symmetric_CBC cbc;

   LTC_ARGCHK(arg           != NULL);
   LTC_ARGCHK(arg->type.kdf != NULL);
   LTC_ARGCHK(dec_data      != NULL);
   LTC_ARGCHK(dec_size      != NULL);

   hid = find_hash(arg->type.h);
   if (hid == -1) return CRYPT_INVALID_HASH;
   cid = find_cipher(arg->type.c);
   if (cid == -1) return CRYPT_INVALID_CIPHER;

   klen = arg->type.keylen;

   /* RC2 special case */
   if (arg->key_bits != 0) {
      /* We can't handle odd lengths of Key Bits */
      if ((arg->key_bits % 8) != 0) return CRYPT_INVALID_KEYSIZE;
      /* Internally we use bytes, not bits */
      klen = arg->key_bits / 8;
   }
   keylen = klen;

   if (arg->iv != NULL) {
      iv = arg->iv->data;
   } else {
      iv = k + klen;
      klen += arg->type.blocklen;
   }

   if (klen > sizeof(k)) return CRYPT_INVALID_ARG;

   if ((err = arg->type.kdf(arg->pwd, arg->pwdlen, arg->salt->data, arg->salt->size, arg->iterations, hid, k, &klen)) != CRYPT_OK) goto LBL_ERROR;
   if ((err = cbc_start(cid, iv, k, keylen, 0, &cbc)) != CRYPT_OK) goto LBL_ERROR;
   if ((err = cbc_decrypt(arg->enc_data->data, dec_data, arg->enc_data->size, &cbc)) != CRYPT_OK) goto LBL_ERROR;
   if ((err = cbc_done(&cbc)) != CRYPT_OK) goto LBL_ERROR;
   dlen = arg->enc_data->size;
   if ((err = padding_depad(dec_data, &dlen, LTC_PAD_PKCS7)) != CRYPT_OK) goto LBL_ERROR;
   diff = (long)arg->enc_data->size - (long)dlen;
   if ((diff <= 0) || (diff > cipher_descriptor[cid].block_length)) {
      err = CRYPT_PK_INVALID_PADDING;
      goto LBL_ERROR;
   }
   *dec_size = dlen;
   return CRYPT_OK;

LBL_ERROR:
   zeromem(k, sizeof(k));
   zeromem(dec_data, *dec_size);
   return err;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
