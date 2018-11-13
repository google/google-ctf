/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_RC4_STREAM

int rc4_stream_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   rc4_state st;
   int err;
   const unsigned char key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
   const unsigned char pt[]  = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
   const unsigned char ct[]  = { 0x75, 0xb7, 0x87, 0x80, 0x99, 0xe0, 0xc5, 0x96 };
   unsigned char buf[10];

   if ((err = rc4_stream_setup(&st, key, sizeof(key))) != CRYPT_OK)    return err;
   if ((err = rc4_stream_crypt(&st, pt, sizeof(pt), buf)) != CRYPT_OK) return err;
   if (compare_testvector(buf, sizeof(ct), ct, sizeof(ct), "RC4-TV1", 0))  return CRYPT_FAIL_TESTVECTOR;
   if ((err = rc4_stream_done(&st)) != CRYPT_OK)                       return err;

   /* crypt in a single call */
   if ((err = rc4_stream_memory(key, sizeof(key), pt, sizeof(pt), buf)) != CRYPT_OK) return err;
   if (compare_testvector(buf, sizeof(ct), ct, sizeof(ct), "RC4-TV2", 0))  return CRYPT_FAIL_TESTVECTOR;

   return CRYPT_OK;
#endif
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
