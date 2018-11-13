/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#include "tomcrypt_private.h"

#ifdef LTC_SOSEMANUK
int sosemanuk_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   sosemanuk_state st;
   int err;
   unsigned char out[1000];

   {
       unsigned char k[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                              0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
       unsigned char n[]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
       unsigned char ct[] = { 0x7e, 0xfe, 0x2e, 0x6f, 0x8f, 0x77, 0x15, 0x72, 0x6a, 0x88, 0x14, 0xa6, 0x56, 0x88, 0x29, 0x9a,
                              0x86, 0x32, 0x7f, 0x14, 0xd6, 0xb1, 0x94, 0x90, 0x25, 0xbc, 0x73, 0xfd, 0x02, 0x6c, 0x6a, 0xb8,
                              0xda, 0x8e, 0x7f, 0x61, 0x70, 0x81, 0xe3, 0xbb, 0x99, 0xaf, 0x19, 0x9f, 0x20, 0x45 };
       char pt[]          = "Kilroy was here, and there. ...and everywhere!";    /* len = 46 bytes */
       unsigned long len;
       len = strlen(pt);
       /* crypt piece by piece */
       if ((err = sosemanuk_setup(&st, k, sizeof(k)))                                != CRYPT_OK) return err;
       if ((err = sosemanuk_setiv(&st, n, sizeof(n)))                                != CRYPT_OK) return err;
       if ((err = sosemanuk_crypt(&st, (unsigned char*)pt,       5,       out))      != CRYPT_OK) return err;
       if ((err = sosemanuk_crypt(&st, (unsigned char*)pt +  5, 25,       out +  5)) != CRYPT_OK) return err;
       if ((err = sosemanuk_crypt(&st, (unsigned char*)pt + 30, 10,       out + 30)) != CRYPT_OK) return err;
       if ((err = sosemanuk_crypt(&st, (unsigned char*)pt + 40, len - 40, out + 40)) != CRYPT_OK) return err;
       if (compare_testvector(out, len, ct, sizeof(ct), "SOSEMANUK-TV1", 1))                      return CRYPT_FAIL_TESTVECTOR;

       /* crypt in one go - using sosemanuk_ivctr64() */
       if ((err = sosemanuk_setup(&st, k, sizeof(k)))                 != CRYPT_OK) return err;
       if ((err = sosemanuk_setiv(&st, n, sizeof(n)))                 != CRYPT_OK) return err;
       if ((err = sosemanuk_crypt(&st, (unsigned char*)pt, len, out)) != CRYPT_OK) return err;
       if (compare_testvector(out, len, ct, sizeof(ct), "SOSEMANUK-TV2", 1))       return CRYPT_FAIL_TESTVECTOR;

       /* crypt in a single call */
       if ((err = sosemanuk_memory(k, sizeof(k), n, sizeof(n),
                                       (unsigned char*)pt, len, out)) != CRYPT_OK) return err;
       if (compare_testvector(out, len, ct, sizeof(ct), "SOSEMANUK-TV3", 1))       return CRYPT_FAIL_TESTVECTOR;

   }
   {
       /* keystream
        * http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/sosemanuk/unverified.test-vectors?rev=210&view=auto
        * Set 6, vector 0
        *                key = 0053A6F94C9FF24598EB3E91E4378ADD
        *                      3083D6297CCF2275C81B6EC11467BA0D
        *                 IV = 0D74DB42A91077DE45AC137AE148AF16
        *      stream[0..63] = 55EB8D174C2E0351E5A53C90E84740EB
        *                      0F5A24AAFEC8E0C9F9D2CE48B2ADB0A3
        *                      4D2E8C4E016102607368FFA43A0F9155
        *                      0706E3548AD9E5EA15A53EB6F0EDE9DC
        *
        */

       unsigned char k3[]  = { 0x00, 0x53, 0xA6, 0xF9, 0x4C, 0x9F, 0xF2, 0x45, 0x98, 0xEB, 0x3E, 0x91, 0xE4, 0x37, 0x8A, 0xDD,
                               0x30, 0x83, 0xD6, 0x29, 0x7C, 0xCF, 0x22, 0x75, 0xC8, 0x1B, 0x6E, 0xC1, 0x14, 0x67, 0xBA, 0x0D };
       unsigned char n3[]  = { 0x0D, 0x74, 0xDB, 0x42, 0xA9, 0x10, 0x77, 0xDE, 0x45, 0xAC, 0x13, 0x7A, 0xE1, 0x48, 0xAF, 0x16 };
       unsigned char ct3[] = { 0x55, 0xEB, 0x8D, 0x17, 0x4C, 0x2E, 0x03, 0x51, 0xE5, 0xA5, 0x3C, 0x90, 0xE8, 0x47, 0x40, 0xEB,
                               0x0F, 0x5A, 0x24, 0xAA, 0xFE, 0xC8, 0xE0, 0xC9, 0xF9, 0xD2, 0xCE, 0x48, 0xB2, 0xAD, 0xB0, 0xA3,
                               0x4D, 0x2E, 0x8C, 0x4E, 0x01, 0x61, 0x02, 0x60, 0x73, 0x68, 0xFF, 0xA4, 0x3A, 0x0F, 0x91, 0x55,
                               0x07, 0x06, 0xE3, 0x54, 0x8A, 0xD9, 0xE5, 0xEA, 0x15, 0xA5, 0x3E, 0xB6, 0xF0, 0xED, 0xE9, 0xDC };
       if ((err = sosemanuk_setup(&st, k3, sizeof(k3)))      != CRYPT_OK)     return err;
       if ((err = sosemanuk_setiv(&st, n3, sizeof(n3)))      != CRYPT_OK)     return err;
       if ((err = sosemanuk_keystream(&st, out, 64))         != CRYPT_OK)     return err;
       if ((err = sosemanuk_done(&st))                       != CRYPT_OK)     return err;
       if (compare_testvector(out, 64, ct3, sizeof(ct3), "SOSEMANUK-TV4", 1)) return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
