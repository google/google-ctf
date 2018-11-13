/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_CHACHA

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with ChaCha
   @param key     The key
   @param keylen  The key length
   @param iv      The initial vector
   @param ivlen   The initial vector length
   @param datain  The plaintext (or ciphertext)
   @param datalen The length of the input and output (octets)
   @param rounds  The number of rounds
   @param dataout [out] The ciphertext (or plaintext)
   @return CRYPT_OK if successful
*/
int chacha_memory(const unsigned char *key,    unsigned long keylen,  unsigned long rounds,
                  const unsigned char *iv,     unsigned long ivlen,   ulong64 counter,
                  const unsigned char *datain, unsigned long datalen, unsigned char *dataout)
{
   chacha_state st;
   int err;

   LTC_ARGCHK(ivlen <= 8 || counter < 4294967296);       /* 2**32 */

   if ((err = chacha_setup(&st, key, keylen, rounds))       != CRYPT_OK) goto WIPE_KEY;
   if (ivlen > 8) {
        if ((err = chacha_ivctr32(&st, iv, ivlen, counter)) != CRYPT_OK) goto WIPE_KEY;
   } else {
        if ((err = chacha_ivctr64(&st, iv, ivlen, counter)) != CRYPT_OK) goto WIPE_KEY;
   }
   err = chacha_crypt(&st, datain, datalen, dataout);
WIPE_KEY:
   chacha_done(&st);
   return err;
}

#endif /* LTC_CHACHA */

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
