/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* The implementation is based on:
 * "Salsa20 specification", http://cr.yp.to/snuffle/spec.pdf
 * and salsa20-ref.c version 20051118
 * Public domain from D. J. Bernstein
 */

#include "tomcrypt_private.h"

#ifdef LTC_SALSA20

int salsa20_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   salsa20_state st;
   unsigned char k[]   = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                           0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
   unsigned char n[]   = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a };
   unsigned char ct[]  = { 0x37, 0x37, 0x2e, 0x60, 0xb8, 0xae, 0x88, 0x1f, 0xf8, 0xdf, 0x00, 0x26, 0x6c, 0x30, 0x34, 0x2d,
                           0xa1, 0xd7, 0x79, 0x60, 0x67, 0x72, 0xe0, 0x67, 0x26, 0x22, 0xad, 0x00, 0x9e, 0xd5, 0x59, 0x44,
                           0x51, 0xd9, 0xe6, 0xaa, 0xc9, 0x59, 0x9e, 0x60, 0xff, 0x87, 0x90, 0xc1, 0xc9, 0x1e };
   unsigned char ct2[] = { 0xec, 0x06, 0x32, 0xb3, 0x83, 0x5c, 0xae, 0x91, 0x01, 0x82, 0x7a, 0x71, 0xd9, 0x7d, 0x45, 0xd7,
                           0xa6, 0x5b, 0xa0, 0x89, 0x9d, 0xd2, 0x6c, 0xaa, 0xbb, 0x2f, 0x5f, 0x30, 0x89, 0x54, 0xff, 0x3e,
                           0x83, 0xc3, 0x34, 0x10, 0xb6, 0xe1, 0xab, 0xe7, 0xf5, 0xab, 0xab, 0xed, 0xa4, 0xff };
   char pt[]           = "Kilroy was here, and there. ...and everywhere!";    /* len = 46 bytes */
   unsigned long len;
   unsigned char out[1000];
   int counter;
   int rounds;
   int err;
   len = strlen(pt);

   /* crypt piece by piece */
   counter = 0;
   rounds  = 12;
   if ((err = salsa20_setup(&st, k, sizeof(k), rounds))                        != CRYPT_OK) return err;
   if ((err = salsa20_ivctr64(&st, n, sizeof(n), counter))                     != CRYPT_OK) return err;
   if ((err = salsa20_crypt(&st, (unsigned char*)pt,       5,       out))      != CRYPT_OK) return err;
   if ((err = salsa20_crypt(&st, (unsigned char*)pt +  5, 25,       out +  5)) != CRYPT_OK) return err;
   if ((err = salsa20_crypt(&st, (unsigned char*)pt + 30, 10,       out + 30)) != CRYPT_OK) return err;
   if ((err = salsa20_crypt(&st, (unsigned char*)pt + 40, len - 40, out + 40)) != CRYPT_OK) return err;
   if (compare_testvector(out, len, ct, sizeof(ct), "SALSA20-TV1", 1))        return CRYPT_FAIL_TESTVECTOR;

   /* crypt in one go - using salsa20_ivctr64() */
   counter = 0;
   rounds  = 20;
   if ((err = salsa20_setup(&st, k, sizeof(k), rounds))         != CRYPT_OK)  return err;
   if ((err = salsa20_ivctr64(&st, n, sizeof(n), counter))      != CRYPT_OK)  return err;
   if ((err = salsa20_crypt(&st, (unsigned char*)pt, len, out)) != CRYPT_OK)  return err;
   if (compare_testvector(out, len, ct2, sizeof(ct2), "SALSA20-TV2", 1))      return CRYPT_FAIL_TESTVECTOR;

   /* crypt in a single call */
   if ((err = salsa20_memory(k, sizeof(k), rounds, n, sizeof(n), counter,
                                 (unsigned char*)pt, len, out)) != CRYPT_OK)  return err;
   if (compare_testvector(out, len, ct2, sizeof(ct2), "SALSA20-TV3", 1))      return CRYPT_FAIL_TESTVECTOR;

   {
       /* keystream
        * http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/salsa20/full/verified.test-vectors?rev=161&view=markup
        * Set 6, vector 0
        */
       unsigned char k3[]  = { 0x00, 0x53, 0xA6, 0xF9, 0x4C, 0x9F, 0xF2, 0x45, 0x98, 0xEB, 0x3E, 0x91, 0xE4, 0x37, 0x8A, 0xDD,
                               0x30, 0x83, 0xD6, 0x29, 0x7C, 0xCF, 0x22, 0x75, 0xC8, 0x1B, 0x6E, 0xC1, 0x14, 0x67, 0xBA, 0x0D };
       unsigned char n3[]  = { 0x0D, 0x74, 0xDB, 0x42, 0xA9, 0x10, 0x77, 0xDE };
       unsigned char ct3[] = { 0xF5, 0xFA, 0xD5, 0x3F, 0x79, 0xF9, 0xDF, 0x58, 0xC4, 0xAE, 0xA0, 0xD0, 0xED, 0x9A, 0x96, 0x01,
                               0xF2, 0x78, 0x11, 0x2C, 0xA7, 0x18, 0x0D, 0x56, 0x5B, 0x42, 0x0A, 0x48, 0x01, 0x96, 0x70, 0xEA,
                               0xF2, 0x4C, 0xE4, 0x93, 0xA8, 0x62, 0x63, 0xF6, 0x77, 0xB4, 0x6A, 0xCE, 0x19, 0x24, 0x77, 0x3D,
                               0x2B, 0xB2, 0x55, 0x71, 0xE1, 0xAA, 0x85, 0x93, 0x75, 0x8F, 0xC3, 0x82, 0xB1, 0x28, 0x0B, 0x71 };
       int counter3 = 0;
       int rounds3  = 20;
       if ((err = salsa20_setup(&st, k3, sizeof(k3), rounds3))    != CRYPT_OK)     return err;
       if ((err = salsa20_ivctr64(&st, n3, sizeof(n3), counter3)) != CRYPT_OK)     return err;
       if ((err = salsa20_keystream(&st, out, 64))                != CRYPT_OK)     return err;
       if ((err = salsa20_done(&st))                              != CRYPT_OK)     return err;
       if (compare_testvector(out, 64, ct3, sizeof(ct3), "SALSA20-TV4", 1))        return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
