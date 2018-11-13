/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* based on https://github.com/brainhub/SHA3IUF (public domain) */

#include "tomcrypt_private.h"

#ifdef LTC_SHA3

int sha3_224_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   unsigned char buf[200], hash[224 / 8];
   int i;
   hash_state c;
   const unsigned char c1 = 0xa3;

   const unsigned char sha3_224_empty[224 / 8] = {
      0x6b, 0x4e, 0x03, 0x42, 0x36, 0x67, 0xdb, 0xb7,
      0x3b, 0x6e, 0x15, 0x45, 0x4f, 0x0e, 0xb1, 0xab,
      0xd4, 0x59, 0x7f, 0x9a, 0x1b, 0x07, 0x8e, 0x3f,
      0x5b, 0x5a, 0x6b, 0xc7
   };

   const unsigned char sha3_224_0xa3_200_times[224 / 8] = {
      0x93, 0x76, 0x81, 0x6a, 0xba, 0x50, 0x3f, 0x72,
      0xf9, 0x6c, 0xe7, 0xeb, 0x65, 0xac, 0x09, 0x5d,
      0xee, 0xe3, 0xbe, 0x4b, 0xf9, 0xbb, 0xc2, 0xa1,
      0xcb, 0x7e, 0x11, 0xe0
   };

   XMEMSET(buf, c1, sizeof(buf));

   /* SHA3-224 on an empty buffer */
   sha3_224_init(&c);
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_224_empty, sizeof(sha3_224_empty), "SHA3-224", 0)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-224 in two steps. [FIPS 202] */
   sha3_224_init(&c);
   sha3_process(&c, buf, sizeof(buf) / 2);
   sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_224_0xa3_200_times, sizeof(sha3_224_0xa3_200_times), "SHA3-224", 1)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-224 byte-by-byte: 200 steps. [FIPS 202] */
   i = 200;
   sha3_224_init(&c);
   while (i--) {
       sha3_process(&c, &c1, 1);
   }
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_224_0xa3_200_times, sizeof(sha3_224_0xa3_200_times), "SHA3-224", 2)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

int sha3_256_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   unsigned char buf[200], hash[256 / 8];
   int i;
   hash_state c;
   const unsigned char c1 = 0xa3;

   const unsigned char sha3_256_empty[256 / 8] = {
      0xa7, 0xff, 0xc6, 0xf8, 0xbf, 0x1e, 0xd7, 0x66,
      0x51, 0xc1, 0x47, 0x56, 0xa0, 0x61, 0xd6, 0x62,
      0xf5, 0x80, 0xff, 0x4d, 0xe4, 0x3b, 0x49, 0xfa,
      0x82, 0xd8, 0x0a, 0x4b, 0x80, 0xf8, 0x43, 0x4a
   };
   const unsigned char sha3_256_0xa3_200_times[256 / 8] = {
      0x79, 0xf3, 0x8a, 0xde, 0xc5, 0xc2, 0x03, 0x07,
      0xa9, 0x8e, 0xf7, 0x6e, 0x83, 0x24, 0xaf, 0xbf,
      0xd4, 0x6c, 0xfd, 0x81, 0xb2, 0x2e, 0x39, 0x73,
      0xc6, 0x5f, 0xa1, 0xbd, 0x9d, 0xe3, 0x17, 0x87
   };

   XMEMSET(buf, c1, sizeof(buf));

   /* SHA3-256 on an empty buffer */
   sha3_256_init(&c);
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_256_empty, sizeof(sha3_256_empty), "SHA3-256", 0)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-256 as a single buffer. [FIPS 202] */
   sha3_256_init(&c);
   sha3_process(&c, buf, sizeof(buf));
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_256_0xa3_200_times, sizeof(sha3_256_0xa3_200_times), "SHA3-256", 1)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-256 in two steps. [FIPS 202] */
   sha3_256_init(&c);
   sha3_process(&c, buf, sizeof(buf) / 2);
   sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_256_0xa3_200_times, sizeof(sha3_256_0xa3_200_times), "SHA3-256", 2)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-256 byte-by-byte: 200 steps. [FIPS 202] */
   i = 200;
   sha3_256_init(&c);
   while (i--) {
       sha3_process(&c, &c1, 1);
   }
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_256_0xa3_200_times, sizeof(sha3_256_0xa3_200_times), "SHA3-256", 3)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-256 byte-by-byte: 135 bytes. Input from [Keccak]. Output
    * matched with sha3sum. */
   sha3_256_init(&c);
   sha3_process(&c, (unsigned char*)
           "\xb7\x71\xd5\xce\xf5\xd1\xa4\x1a"
           "\x93\xd1\x56\x43\xd7\x18\x1d\x2a"
           "\x2e\xf0\xa8\xe8\x4d\x91\x81\x2f"
           "\x20\xed\x21\xf1\x47\xbe\xf7\x32"
           "\xbf\x3a\x60\xef\x40\x67\xc3\x73"
           "\x4b\x85\xbc\x8c\xd4\x71\x78\x0f"
           "\x10\xdc\x9e\x82\x91\xb5\x83\x39"
           "\xa6\x77\xb9\x60\x21\x8f\x71\xe7"
           "\x93\xf2\x79\x7a\xea\x34\x94\x06"
           "\x51\x28\x29\x06\x5d\x37\xbb\x55"
           "\xea\x79\x6f\xa4\xf5\x6f\xd8\x89"
           "\x6b\x49\xb2\xcd\x19\xb4\x32\x15"
           "\xad\x96\x7c\x71\x2b\x24\xe5\x03"
           "\x2d\x06\x52\x32\xe0\x2c\x12\x74"
           "\x09\xd2\xed\x41\x46\xb9\xd7\x5d"
           "\x76\x3d\x52\xdb\x98\xd9\x49\xd3"
           "\xb0\xfe\xd6\xa8\x05\x2f\xbb", 1080 / 8);
   sha3_done(&c, hash);
   if(compare_testvector(hash, sizeof(hash),
           "\xa1\x9e\xee\x92\xbb\x20\x97\xb6"
           "\x4e\x82\x3d\x59\x77\x98\xaa\x18"
           "\xbe\x9b\x7c\x73\x6b\x80\x59\xab"
           "\xfd\x67\x79\xac\x35\xac\x81\xb5", 256 / 8, "SHA3-256", 4)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

int sha3_384_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   unsigned char buf[200], hash[384 / 8];
   int i;
   hash_state c;
   const unsigned char c1 = 0xa3;

   const unsigned char sha3_384_0xa3_200_times[384 / 8] = {
      0x18, 0x81, 0xde, 0x2c, 0xa7, 0xe4, 0x1e, 0xf9,
      0x5d, 0xc4, 0x73, 0x2b, 0x8f, 0x5f, 0x00, 0x2b,
      0x18, 0x9c, 0xc1, 0xe4, 0x2b, 0x74, 0x16, 0x8e,
      0xd1, 0x73, 0x26, 0x49, 0xce, 0x1d, 0xbc, 0xdd,
      0x76, 0x19, 0x7a, 0x31, 0xfd, 0x55, 0xee, 0x98,
      0x9f, 0x2d, 0x70, 0x50, 0xdd, 0x47, 0x3e, 0x8f
   };

   XMEMSET(buf, c1, sizeof(buf));

   /* SHA3-384 as a single buffer. [FIPS 202] */
   sha3_384_init(&c);
   sha3_process(&c, buf, sizeof(buf));
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_384_0xa3_200_times, sizeof(sha3_384_0xa3_200_times), "SHA3-384", 0)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-384 in two steps. [FIPS 202] */
   sha3_384_init(&c);
   sha3_process(&c, buf, sizeof(buf) / 2);
   sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_384_0xa3_200_times, sizeof(sha3_384_0xa3_200_times), "SHA3-384", 1)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-384 byte-by-byte: 200 steps. [FIPS 202] */
   i = 200;
   sha3_384_init(&c);
   while (i--) {
       sha3_process(&c, &c1, 1);
   }
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_384_0xa3_200_times, sizeof(sha3_384_0xa3_200_times), "SHA3-384", 2)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

int sha3_512_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   unsigned char buf[200], hash[512 / 8];
   int i;
   hash_state c;
   const unsigned char c1 = 0xa3;

   const unsigned char sha3_512_0xa3_200_times[512 / 8] = {
      0xe7, 0x6d, 0xfa, 0xd2, 0x20, 0x84, 0xa8, 0xb1,
      0x46, 0x7f, 0xcf, 0x2f, 0xfa, 0x58, 0x36, 0x1b,
      0xec, 0x76, 0x28, 0xed, 0xf5, 0xf3, 0xfd, 0xc0,
      0xe4, 0x80, 0x5d, 0xc4, 0x8c, 0xae, 0xec, 0xa8,
      0x1b, 0x7c, 0x13, 0xc3, 0x0a, 0xdf, 0x52, 0xa3,
      0x65, 0x95, 0x84, 0x73, 0x9a, 0x2d, 0xf4, 0x6b,
      0xe5, 0x89, 0xc5, 0x1c, 0xa1, 0xa4, 0xa8, 0x41,
      0x6d, 0xf6, 0x54, 0x5a, 0x1c, 0xe8, 0xba, 0x00
   };

   XMEMSET(buf, c1, sizeof(buf));

   /* SHA3-512 as a single buffer. [FIPS 202] */
   sha3_512_init(&c);
   sha3_process(&c, buf, sizeof(buf));
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 0)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-512 in two steps. [FIPS 202] */
   sha3_512_init(&c);
   sha3_process(&c, buf, sizeof(buf) / 2);
   sha3_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 1)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHA3-512 byte-by-byte: 200 steps. [FIPS 202] */
   i = 200;
   sha3_512_init(&c);
   while (i--) {
       sha3_process(&c, &c1, 1);
   }
   sha3_done(&c, hash);
   if (compare_testvector(hash, sizeof(hash), sha3_512_0xa3_200_times, sizeof(sha3_512_0xa3_200_times), "SHA3-512", 2)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

int sha3_shake_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   unsigned char buf[200], hash[512];
   int i;
   hash_state c;
   const unsigned char c1 = 0xa3;
   unsigned long len;

   const unsigned char shake256_empty[32] = {
      0xab, 0x0b, 0xae, 0x31, 0x63, 0x39, 0x89, 0x43,
      0x04, 0xe3, 0x58, 0x77, 0xb0, 0xc2, 0x8a, 0x9b,
      0x1f, 0xd1, 0x66, 0xc7, 0x96, 0xb9, 0xcc, 0x25,
      0x8a, 0x06, 0x4a, 0x8f, 0x57, 0xe2, 0x7f, 0x2a
   };
   const unsigned char shake256_0xa3_200_times[32] = {
      0x6a, 0x1a, 0x9d, 0x78, 0x46, 0x43, 0x6e, 0x4d,
      0xca, 0x57, 0x28, 0xb6, 0xf7, 0x60, 0xee, 0xf0,
      0xca, 0x92, 0xbf, 0x0b, 0xe5, 0x61, 0x5e, 0x96,
      0x95, 0x9d, 0x76, 0x71, 0x97, 0xa0, 0xbe, 0xeb
   };
   const unsigned char shake128_empty[32] = {
      0x43, 0xe4, 0x1b, 0x45, 0xa6, 0x53, 0xf2, 0xa5,
      0xc4, 0x49, 0x2c, 0x1a, 0xdd, 0x54, 0x45, 0x12,
      0xdd, 0xa2, 0x52, 0x98, 0x33, 0x46, 0x2b, 0x71,
      0xa4, 0x1a, 0x45, 0xbe, 0x97, 0x29, 0x0b, 0x6f
   };
   const unsigned char shake128_0xa3_200_times[32] = {
      0x44, 0xc9, 0xfb, 0x35, 0x9f, 0xd5, 0x6a, 0xc0,
      0xa9, 0xa7, 0x5a, 0x74, 0x3c, 0xff, 0x68, 0x62,
      0xf1, 0x7d, 0x72, 0x59, 0xab, 0x07, 0x52, 0x16,
      0xc0, 0x69, 0x95, 0x11, 0x64, 0x3b, 0x64, 0x39
   };

   XMEMSET(buf, c1, sizeof(buf));

   /* SHAKE256 on an empty buffer */
   sha3_shake_init(&c, 256);
   for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
   if (compare_testvector(hash, sizeof(shake256_empty), shake256_empty, sizeof(shake256_empty), "SHAKE256", 0)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE256 via sha3_shake_memory [FIPS 202] */
   len = 512;
   sha3_shake_memory(256, buf, sizeof(buf), hash, &len);
   if (compare_testvector(hash + 480, sizeof(shake256_0xa3_200_times), shake256_0xa3_200_times, sizeof(shake256_0xa3_200_times), "SHAKE256", 1)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE256 as a single buffer. [FIPS 202] */
   sha3_shake_init(&c, 256);
   sha3_shake_process(&c, buf, sizeof(buf));
   for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
   if (compare_testvector(hash, sizeof(shake256_0xa3_200_times), shake256_0xa3_200_times, sizeof(shake256_0xa3_200_times), "SHAKE256", 2)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE256 in two steps. [FIPS 202] */
   sha3_shake_init(&c, 256);
   sha3_shake_process(&c, buf, sizeof(buf) / 2);
   sha3_shake_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
   for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
   if (compare_testvector(hash, sizeof(shake256_0xa3_200_times), shake256_0xa3_200_times, sizeof(shake256_0xa3_200_times), "SHAKE256", 3)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE256 byte-by-byte: 200 steps. [FIPS 202] */
   i = 200;
   sha3_shake_init(&c, 256);
   while (i--) sha3_shake_process(&c, &c1, 1);
   for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
   if (compare_testvector(hash, sizeof(shake256_0xa3_200_times), shake256_0xa3_200_times, sizeof(shake256_0xa3_200_times), "SHAKE256", 4)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE128 on an empty buffer */
   sha3_shake_init(&c, 128);
   for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
   if (compare_testvector(hash, sizeof(shake128_empty), shake128_empty, sizeof(shake128_empty), "SHAKE128", 0)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE128 via sha3_shake_memory [FIPS 202] */
   len = 512;
   sha3_shake_memory(128, buf, sizeof(buf), hash, &len);
   if (compare_testvector(hash + 480, sizeof(shake128_0xa3_200_times), shake128_0xa3_200_times, sizeof(shake128_0xa3_200_times), "SHAKE128", 1)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE128 as a single buffer. [FIPS 202] */
   sha3_shake_init(&c, 128);
   sha3_shake_process(&c, buf, sizeof(buf));
   for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
   if (compare_testvector(hash, sizeof(shake128_0xa3_200_times), shake128_0xa3_200_times, sizeof(shake128_0xa3_200_times), "SHAKE128", 2)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE128 in two steps. [FIPS 202] */
   sha3_shake_init(&c, 128);
   sha3_shake_process(&c, buf, sizeof(buf) / 2);
   sha3_shake_process(&c, buf + sizeof(buf) / 2, sizeof(buf) / 2);
   for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
   if (compare_testvector(hash, sizeof(shake128_0xa3_200_times), shake128_0xa3_200_times, sizeof(shake128_0xa3_200_times), "SHAKE128", 3)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   /* SHAKE128 byte-by-byte: 200 steps. [FIPS 202] */
   i = 200;
   sha3_shake_init(&c, 128);
   while (i--) sha3_shake_process(&c, &c1, 1);
   for (i = 0; i < 16; i++) sha3_shake_done(&c, hash, 32); /* get 512 bytes, keep in hash the last 32 */
   if (compare_testvector(hash, sizeof(shake128_0xa3_200_times), shake128_0xa3_200_times, sizeof(shake128_0xa3_200_times), "SHAKE128", 4)) {
      return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

#endif

#ifdef LTC_KECCAK

int keccak_224_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   hash_state c;
   unsigned char hash[MAXBLOCKSIZE];

   keccak_224_init(&c);
   keccak_process(&c, (unsigned char*) "\xcc", 1);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 28,
                         "\xa9\xca\xb5\x9e\xb4\x0a\x10\xb2"
                         "\x46\x29\x0f\x2d\x60\x86\xe3\x2e"
                         "\x36\x89\xfa\xf1\xd2\x6b\x47\x0c"
                         "\x89\x9f\x28\x02", 28,
                         "KECCAK-224", 0) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_224_init(&c);
   keccak_process(&c, (unsigned char*)"\x41\xfb", 2);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 28,
                         "\x61\x5b\xa3\x67\xaf\xdc\x35\xaa"
                         "\xc3\x97\xbc\x7e\xb5\xd5\x8d\x10"
                         "\x6a\x73\x4b\x24\x98\x6d\x5d\x97"
                         "\x8f\xef\xd6\x2c", 28,
                         "KECCAK-224", 1) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_224_init(&c);
   keccak_process(&c, (unsigned char*)
                    "\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
                    "\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 28,
                         "\x56\x79\xcd\x50\x9c\x51\x20\xaf"
                         "\x54\x79\x5c\xf4\x77\x14\x96\x41"
                         "\xcf\x27\xb2\xeb\xb6\xa5\xf9\x03"
                         "\x40\x70\x4e\x57", 28,
                         "KECCAK-224", 2) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_224_init(&c);
   keccak_process(&c, (unsigned char*)
                    "\x43\x3c\x53\x03\x13\x16\x24\xc0"
                    "\x02\x1d\x86\x8a\x30\x82\x54\x75"
                    "\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
                    "\x03\x98\xf4\xca\x44\x23\xb9\x82"
                    "\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
                    "\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
                    "\x92\xcc\x1b\x06\xce\xdf\x32\x24"
                    "\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
                    "\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
                    "\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
                    "\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
                    "\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
                    "\x6d\xcb\xb4\xce", 100);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 28,
                         "\x62\xb1\x0f\x1b\x62\x36\xeb\xc2"
                         "\xda\x72\x95\x77\x42\xa8\xd4\xe4"
                         "\x8e\x21\x3b\x5f\x89\x34\x60\x4b"
                         "\xfd\x4d\x2c\x3a", 28,
                         "KECCAK-224", 3) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

int keccak_256_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   hash_state c;
   unsigned char hash[MAXBLOCKSIZE];

   keccak_256_init(&c);
   keccak_process(&c, (unsigned char*) "\xcc", 1);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 32,
                         "\xee\xad\x6d\xbf\xc7\x34\x0a\x56"
                         "\xca\xed\xc0\x44\x69\x6a\x16\x88"
                         "\x70\x54\x9a\x6a\x7f\x6f\x56\x96"
                         "\x1e\x84\xa5\x4b\xd9\x97\x0b\x8a", 32,
                         "KECCAK-256", 0) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_256_init(&c);
   keccak_process(&c, (unsigned char*)"\x41\xfb", 2);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 32,
                         "\xa8\xea\xce\xda\x4d\x47\xb3\x28"
                         "\x1a\x79\x5a\xd9\xe1\xea\x21\x22"
                         "\xb4\x07\xba\xf9\xaa\xbc\xb9\xe1"
                         "\x8b\x57\x17\xb7\x87\x35\x37\xd2", 32,
                         "KECCAK-256", 1) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_256_init(&c);
   keccak_process(&c, (unsigned char*)
                    "\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
                    "\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 32,
                         "\x0e\x32\xde\xfa\x20\x71\xf0\xb5"
                         "\xac\x0e\x6a\x10\x8b\x84\x2e\xd0"
                         "\xf1\xd3\x24\x97\x12\xf5\x8e\xe0"
                         "\xdd\xf9\x56\xfe\x33\x2a\x5f\x95", 32,
                         "KECCAK-256", 2) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_256_init(&c);
   keccak_process(&c, (unsigned char*)
                    "\x43\x3c\x53\x03\x13\x16\x24\xc0"
                    "\x02\x1d\x86\x8a\x30\x82\x54\x75"
                    "\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
                    "\x03\x98\xf4\xca\x44\x23\xb9\x82"
                    "\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
                    "\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
                    "\x92\xcc\x1b\x06\xce\xdf\x32\x24"
                    "\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
                    "\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
                    "\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
                    "\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
                    "\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
                    "\x6d\xcb\xb4\xce", 100);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 32,
                         "\xce\x87\xa5\x17\x3b\xff\xd9\x23"
                         "\x99\x22\x16\x58\xf8\x01\xd4\x5c"
                         "\x29\x4d\x90\x06\xee\x9f\x3f\x9d"
                         "\x41\x9c\x8d\x42\x77\x48\xdc\x41", 32,
                         "KECCAK-256", 3) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

int keccak_384_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   hash_state c;
   unsigned char hash[MAXBLOCKSIZE];

   keccak_384_init(&c);
   keccak_process(&c, (unsigned char*) "\xcc", 1);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 48,
                         "\x1b\x84\xe6\x2a\x46\xe5\xa2\x01"
                         "\x86\x17\x54\xaf\x5d\xc9\x5c\x4a"
                         "\x1a\x69\xca\xf4\xa7\x96\xae\x40"
                         "\x56\x80\x16\x1e\x29\x57\x26\x41"
                         "\xf5\xfa\x1e\x86\x41\xd7\x95\x83"
                         "\x36\xee\x7b\x11\xc5\x8f\x73\xe9", 48,
                         "KECCAK-384", 0) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_384_init(&c);
   keccak_process(&c, (unsigned char*)"\x41\xfb", 2);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 48,
                         "\x49\x5c\xce\x27\x14\xcd\x72\xc8"
                         "\xc5\x3c\x33\x63\xd2\x2c\x58\xb5"
                         "\x59\x60\xfe\x26\xbe\x0b\xf3\xbb"
                         "\xc7\xa3\x31\x6d\xd5\x63\xad\x1d"
                         "\xb8\x41\x0e\x75\xee\xfe\xa6\x55"
                         "\xe3\x9d\x46\x70\xec\x0b\x17\x92", 48,
                         "KECCAK-384", 1) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_384_init(&c);
   keccak_process(&c, (unsigned char*)
                    "\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
                    "\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 48,
                         "\x18\x42\x2a\xc1\xd3\xa1\xe5\x4b"
                         "\xad\x87\x68\x83\xd2\xd6\xdd\x65"
                         "\xf6\x5c\x1d\x5f\x33\xa7\x12\x5c"
                         "\xc4\xc1\x86\x40\x5a\x12\xed\x64"
                         "\xba\x96\x67\x2e\xed\xda\x8c\x5a"
                         "\x63\x31\xd2\x86\x83\xf4\x88\xeb", 48,
                         "KECCAK-384", 2) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_384_init(&c);
   keccak_process(&c, (unsigned char*)
                    "\x43\x3c\x53\x03\x13\x16\x24\xc0"
                    "\x02\x1d\x86\x8a\x30\x82\x54\x75"
                    "\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
                    "\x03\x98\xf4\xca\x44\x23\xb9\x82"
                    "\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
                    "\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
                    "\x92\xcc\x1b\x06\xce\xdf\x32\x24"
                    "\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
                    "\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
                    "\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
                    "\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
                    "\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
                    "\x6d\xcb\xb4\xce", 100);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 48,
                         "\x13\x51\x14\x50\x8d\xd6\x3e\x27"
                         "\x9e\x70\x9c\x26\xf7\x81\x7c\x04"
                         "\x82\x76\x6c\xde\x49\x13\x2e\x3e"
                         "\xdf\x2e\xed\xd8\x99\x6f\x4e\x35"
                         "\x96\xd1\x84\x10\x0b\x38\x48\x68"
                         "\x24\x9f\x1d\x8b\x8f\xda\xa2\xc9", 48,
                         "KECCAK-384", 3) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

int keccak_512_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   hash_state c;
   unsigned char hash[MAXBLOCKSIZE];

   keccak_512_init(&c);
   keccak_process(&c, (unsigned char*) "\xcc", 1);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 64,
                         "\x86\x30\xc1\x3c\xbd\x06\x6e\xa7"
                         "\x4b\xbe\x7f\xe4\x68\xfe\xc1\xde"
                         "\xe1\x0e\xdc\x12\x54\xfb\x4c\x1b"
                         "\x7c\x5f\xd6\x9b\x64\x6e\x44\x16"
                         "\x0b\x8c\xe0\x1d\x05\xa0\x90\x8c"
                         "\xa7\x90\xdf\xb0\x80\xf4\xb5\x13"
                         "\xbc\x3b\x62\x25\xec\xe7\xa8\x10"
                         "\x37\x14\x41\xa5\xac\x66\x6e\xb9", 64,
                         "KECCAK-512", 0) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_512_init(&c);
   keccak_process(&c, (unsigned char*)"\x41\xfb", 2);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 64,
                         "\x55\x1d\xa6\x23\x6f\x8b\x96\xfc"
                         "\xe9\xf9\x7f\x11\x90\xe9\x01\x32"
                         "\x4f\x0b\x45\xe0\x6d\xbb\xb5\xcd"
                         "\xb8\x35\x5d\x6e\xd1\xdc\x34\xb3"
                         "\xf0\xea\xe7\xdc\xb6\x86\x22\xff"
                         "\x23\x2f\xa3\xce\xce\x0d\x46\x16"
                         "\xcd\xeb\x39\x31\xf9\x38\x03\x66"
                         "\x2a\x28\xdf\x1c\xd5\x35\xb7\x31", 64,
                         "KECCAK-512", 1) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_512_init(&c);
   keccak_process(&c, (unsigned char*)
                    "\x52\xa6\x08\xab\x21\xcc\xdd\x8a"
                    "\x44\x57\xa5\x7e\xde\x78\x21\x76", 16);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 64,
                         "\x4b\x39\xd3\xda\x5b\xcd\xf4\xd9"
                         "\xb7\x69\x01\x59\x95\x64\x43\x11"
                         "\xc1\x4c\x43\x5b\xf7\x2b\x10\x09"
                         "\xd6\xdd\x71\xb0\x1a\x63\xb9\x7c"
                         "\xfb\x59\x64\x18\xe8\xe4\x23\x42"
                         "\xd1\x17\xe0\x74\x71\xa8\x91\x43"
                         "\x14\xba\x7b\x0e\x26\x4d\xad\xf0"
                         "\xce\xa3\x81\x86\x8c\xbd\x43\xd1", 64,
                         "KECCAK-512", 2) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   keccak_512_init(&c);
   keccak_process(&c, (unsigned char*)
                    "\x43\x3c\x53\x03\x13\x16\x24\xc0"
                    "\x02\x1d\x86\x8a\x30\x82\x54\x75"
                    "\xe8\xd0\xbd\x30\x52\xa0\x22\x18"
                    "\x03\x98\xf4\xca\x44\x23\xb9\x82"
                    "\x14\xb6\xbe\xaa\xc2\x1c\x88\x07"
                    "\xa2\xc3\x3f\x8c\x93\xbd\x42\xb0"
                    "\x92\xcc\x1b\x06\xce\xdf\x32\x24"
                    "\xd5\xed\x1e\xc2\x97\x84\x44\x4f"
                    "\x22\xe0\x8a\x55\xaa\x58\x54\x2b"
                    "\x52\x4b\x02\xcd\x3d\x5d\x5f\x69"
                    "\x07\xaf\xe7\x1c\x5d\x74\x62\x22"
                    "\x4a\x3f\x9d\x9e\x53\xe7\xe0\x84"
                    "\x6d\xcb\xb4\xce", 100);
   keccak_done(&c, hash);
   if(compare_testvector(hash, 64,
                         "\x52\x7d\x28\xe3\x41\xe6\xb1\x4f"
                         "\x46\x84\xad\xb4\xb8\x24\xc4\x96"
                         "\xc6\x48\x2e\x51\x14\x95\x65\xd3"
                         "\xd1\x72\x26\x82\x88\x84\x30\x6b"
                         "\x51\xd6\x14\x8a\x72\x62\x2c\x2b"
                         "\x75\xf5\xd3\x51\x0b\x79\x9d\x8b"
                         "\xdc\x03\xea\xed\xe4\x53\x67\x6a"
                         "\x6e\xc8\xfe\x03\xa1\xad\x0e\xab", 64,
                         "KECCAK-512", 3) != 0) {
       return CRYPT_FAIL_TESTVECTOR;
   }

   return CRYPT_OK;
#endif
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
