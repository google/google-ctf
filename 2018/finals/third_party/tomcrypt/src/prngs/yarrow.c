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
  @file yarrow.c
  Yarrow PRNG, Tom St Denis
*/

#ifdef LTC_YARROW

const struct ltc_prng_descriptor yarrow_desc =
{
    "yarrow", 64,
    &yarrow_start,
    &yarrow_add_entropy,
    &yarrow_ready,
    &yarrow_read,
    &yarrow_done,
    &yarrow_export,
    &yarrow_import,
    &yarrow_test
};

/**
  Start the PRNG
  @param prng     [out] The PRNG state to initialize
  @return CRYPT_OK if successful
*/
int yarrow_start(prng_state *prng)
{
   int err;

   LTC_ARGCHK(prng != NULL);
   prng->ready = 0;

   /* these are the default hash/cipher combo used */
#ifdef LTC_RIJNDAEL
#if    LTC_YARROW_AES==0
   prng->u.yarrow.cipher = register_cipher(&rijndael_enc_desc);
#elif  LTC_YARROW_AES==1
   prng->u.yarrow.cipher = register_cipher(&aes_enc_desc);
#elif  LTC_YARROW_AES==2
   prng->u.yarrow.cipher = register_cipher(&rijndael_desc);
#elif  LTC_YARROW_AES==3
   prng->u.yarrow.cipher = register_cipher(&aes_desc);
#endif
#elif defined(LTC_BLOWFISH)
   prng->u.yarrow.cipher = register_cipher(&blowfish_desc);
#elif defined(LTC_TWOFISH)
   prng->u.yarrow.cipher = register_cipher(&twofish_desc);
#elif defined(LTC_RC6)
   prng->u.yarrow.cipher = register_cipher(&rc6_desc);
#elif defined(LTC_RC5)
   prng->u.yarrow.cipher = register_cipher(&rc5_desc);
#elif defined(LTC_SAFERP)
   prng->u.yarrow.cipher = register_cipher(&saferp_desc);
#elif defined(LTC_RC2)
   prng->u.yarrow.cipher = register_cipher(&rc2_desc);
#elif defined(LTC_NOEKEON)
   prng->u.yarrow.cipher = register_cipher(&noekeon_desc);
#elif defined(LTC_ANUBIS)
   prng->u.yarrow.cipher = register_cipher(&anubis_desc);
#elif defined(LTC_KSEED)
   prng->u.yarrow.cipher = register_cipher(&kseed_desc);
#elif defined(LTC_KHAZAD)
   prng->u.yarrow.cipher = register_cipher(&khazad_desc);
#elif defined(LTC_CAST5)
   prng->u.yarrow.cipher = register_cipher(&cast5_desc);
#elif defined(LTC_XTEA)
   prng->u.yarrow.cipher = register_cipher(&xtea_desc);
#elif defined(LTC_SAFER)
   prng->u.yarrow.cipher = register_cipher(&safer_sk128_desc);
#elif defined(LTC_DES)
   prng->u.yarrow.cipher = register_cipher(&des3_desc);
#else
   #error LTC_YARROW needs at least one CIPHER
#endif
   if ((err = cipher_is_valid(prng->u.yarrow.cipher)) != CRYPT_OK) {
      return err;
   }

#ifdef LTC_SHA256
   prng->u.yarrow.hash   = register_hash(&sha256_desc);
#elif defined(LTC_SHA512)
   prng->u.yarrow.hash   = register_hash(&sha512_desc);
#elif defined(LTC_TIGER)
   prng->u.yarrow.hash   = register_hash(&tiger_desc);
#elif defined(LTC_SHA1)
   prng->u.yarrow.hash   = register_hash(&sha1_desc);
#elif defined(LTC_RIPEMD320)
   prng->u.yarrow.hash   = register_hash(&rmd320_desc);
#elif defined(LTC_RIPEMD256)
   prng->u.yarrow.hash   = register_hash(&rmd256_desc);
#elif defined(LTC_RIPEMD160)
   prng->u.yarrow.hash   = register_hash(&rmd160_desc);
#elif defined(LTC_RIPEMD128)
   prng->u.yarrow.hash   = register_hash(&rmd128_desc);
#elif defined(LTC_MD5)
   prng->u.yarrow.hash   = register_hash(&md5_desc);
#elif defined(LTC_MD4)
   prng->u.yarrow.hash   = register_hash(&md4_desc);
#elif defined(LTC_MD2)
   prng->u.yarrow.hash   = register_hash(&md2_desc);
#elif defined(LTC_WHIRLPOOL)
   prng->u.yarrow.hash   = register_hash(&whirlpool_desc);
#else
   #error LTC_YARROW needs at least one HASH
#endif
   if ((err = hash_is_valid(prng->u.yarrow.hash)) != CRYPT_OK) {
      return err;
   }

   /* zero the memory used */
   zeromem(prng->u.yarrow.pool, sizeof(prng->u.yarrow.pool));
   LTC_MUTEX_INIT(&prng->lock)

   return CRYPT_OK;
}

/**
  Add entropy to the PRNG state
  @param in       The data to add
  @param inlen    Length of the data to add
  @param prng     PRNG state to update
  @return CRYPT_OK if successful
*/
int yarrow_add_entropy(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   hash_state md;
   int err;

   LTC_ARGCHK(prng != NULL);
   LTC_ARGCHK(in != NULL);
   LTC_ARGCHK(inlen > 0);

   LTC_MUTEX_LOCK(&prng->lock);

   if ((err = hash_is_valid(prng->u.yarrow.hash)) != CRYPT_OK) {
      goto LBL_UNLOCK;
   }

   /* start the hash */
   if ((err = hash_descriptor[prng->u.yarrow.hash].init(&md)) != CRYPT_OK) {
      goto LBL_UNLOCK;
   }

   /* hash the current pool */
   if ((err = hash_descriptor[prng->u.yarrow.hash].process(&md, prng->u.yarrow.pool,
                                                        hash_descriptor[prng->u.yarrow.hash].hashsize)) != CRYPT_OK) {
      goto LBL_UNLOCK;
   }

   /* add the new entropy */
   if ((err = hash_descriptor[prng->u.yarrow.hash].process(&md, in, inlen)) != CRYPT_OK) {
      goto LBL_UNLOCK;
   }

   /* store result */
   err = hash_descriptor[prng->u.yarrow.hash].done(&md, prng->u.yarrow.pool);

LBL_UNLOCK:
   LTC_MUTEX_UNLOCK(&prng->lock);
   return err;
}

/**
  Make the PRNG ready to read from
  @param prng   The PRNG to make active
  @return CRYPT_OK if successful
*/
int yarrow_ready(prng_state *prng)
{
   int ks, err;

   LTC_ARGCHK(prng != NULL);

   LTC_MUTEX_LOCK(&prng->lock);

   if ((err = hash_is_valid(prng->u.yarrow.hash)) != CRYPT_OK) {
      goto LBL_UNLOCK;
   }

   if ((err = cipher_is_valid(prng->u.yarrow.cipher)) != CRYPT_OK) {
      goto LBL_UNLOCK;
   }

   /* setup CTR mode using the "pool" as the key */
   ks = (int)hash_descriptor[prng->u.yarrow.hash].hashsize;
   if ((err = cipher_descriptor[prng->u.yarrow.cipher].keysize(&ks)) != CRYPT_OK) {
      goto LBL_UNLOCK;
   }

   if ((err = ctr_start(prng->u.yarrow.cipher,     /* what cipher to use */
                        prng->u.yarrow.pool,       /* IV */
                        prng->u.yarrow.pool, ks,   /* KEY and key size */
                        0,                       /* number of rounds */
                        CTR_COUNTER_LITTLE_ENDIAN, /* little endian counter */
                        &prng->u.yarrow.ctr)) != CRYPT_OK) {
      goto LBL_UNLOCK;
   }
   prng->ready = 1;

LBL_UNLOCK:
   LTC_MUTEX_UNLOCK(&prng->lock);
   return err;
}

/**
  Read from the PRNG
  @param out      Destination
  @param outlen   Length of output
  @param prng     The active PRNG to read from
  @return Number of octets read
*/
unsigned long yarrow_read(unsigned char *out, unsigned long outlen, prng_state *prng)
{
   if (outlen == 0 || prng == NULL || out == NULL) return 0;

   LTC_MUTEX_LOCK(&prng->lock);

   if (!prng->ready) {
      outlen = 0;
      goto LBL_UNLOCK;
   }

   /* put out in predictable state first */
   zeromem(out, outlen);

   /* now randomize it */
   if (ctr_encrypt(out, out, outlen, &prng->u.yarrow.ctr) != CRYPT_OK) {
      outlen = 0;
   }

LBL_UNLOCK:
   LTC_MUTEX_UNLOCK(&prng->lock);
   return outlen;
}

/**
  Terminate the PRNG
  @param prng   The PRNG to terminate
  @return CRYPT_OK if successful
*/
int yarrow_done(prng_state *prng)
{
   int err;
   LTC_ARGCHK(prng != NULL);

   LTC_MUTEX_LOCK(&prng->lock);
   prng->ready = 0;

   /* call cipher done when we invent one ;-) */

   /* we invented one */
   err = ctr_done(&prng->u.yarrow.ctr);

   LTC_MUTEX_UNLOCK(&prng->lock);
   LTC_MUTEX_DESTROY(&prng->lock);
   return err;
}

/**
  Export the PRNG state
  @param out       [out] Destination
  @param outlen    [in/out] Max size and resulting size of the state
  @param prng      The PRNG to export
  @return CRYPT_OK if successful
*/
_LTC_PRNG_EXPORT(yarrow)

/**
  Import a PRNG state
  @param in       The PRNG state
  @param inlen    Size of the state
  @param prng     The PRNG to import
  @return CRYPT_OK if successful
*/
int yarrow_import(const unsigned char *in, unsigned long inlen, prng_state *prng)
{
   int err;

   LTC_ARGCHK(in   != NULL);
   LTC_ARGCHK(prng != NULL);
   if (inlen < (unsigned long)yarrow_desc.export_size) return CRYPT_INVALID_ARG;

   if ((err = yarrow_start(prng)) != CRYPT_OK)                  return err;
   if ((err = yarrow_add_entropy(in, inlen, prng)) != CRYPT_OK) return err;
   return CRYPT_OK;
}

/**
  PRNG self-test
  @return CRYPT_OK if successful, CRYPT_NOP if self-testing has been disabled
*/
int yarrow_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   int err;
   prng_state prng;

   if ((err = yarrow_start(&prng)) != CRYPT_OK) {
      return err;
   }

   /* now let's test the hash/cipher that was chosen */
   if (cipher_descriptor[prng.u.yarrow.cipher].test &&
       ((err = cipher_descriptor[prng.u.yarrow.cipher].test()) != CRYPT_OK)) {
      return err;
   }
   if (hash_descriptor[prng.u.yarrow.hash].test &&
       ((err = hash_descriptor[prng.u.yarrow.hash].test()) != CRYPT_OK)) {
      return err;
   }

   return CRYPT_OK;
#endif
}

#endif


/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
