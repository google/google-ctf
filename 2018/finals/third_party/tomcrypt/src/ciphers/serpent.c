/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* Based on serpent.cpp - originally written and placed in the public domain by Wei Dai
   https://github.com/weidai11/cryptopp/blob/master/serpent.cpp

   On 2017-10-16 wikipedia says:
   "The Serpent cipher algorithm is in the public domain and has not been patented."
   https://en.wikipedia.org/wiki/Serpent_(cipher)
 */

#include "tomcrypt_private.h"

#ifdef LTC_SERPENT

const struct ltc_cipher_descriptor serpent_desc = {
   "serpent",
   25,                  /* cipher_ID */
   16, 32, 16, 32,      /* min_key_len, max_key_len, block_len, default_rounds */
   &serpent_setup,
   &serpent_ecb_encrypt,
   &serpent_ecb_decrypt,
   &serpent_test,
   &serpent_done,
   &serpent_keysize,
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* linear transformation */
#define _LT(i,a,b,c,d,e)  {                                 \
                            a = ROLc(a, 13);                \
                            c = ROLc(c, 3);                 \
                            d = ROLc(d ^ c ^ (a << 3), 7);  \
                            b = ROLc(b ^ a ^ c, 1);         \
                            a = ROLc(a ^ b ^ d, 5);         \
                            c = ROLc(c ^ d ^ (b << 7), 22); \
                          }

/* inverse linear transformation */
#define _ILT(i,a,b,c,d,e) {                                 \
                            c = RORc(c, 22);                \
                            a = RORc(a, 5);                 \
                            c ^= d ^ (b << 7);              \
                            a ^= b ^ d;                     \
                            b = RORc(b, 1);                 \
                            d = RORc(d, 7) ^ c ^ (a << 3);  \
                            b ^= a ^ c;                     \
                            c = RORc(c, 3);                 \
                            a = RORc(a, 13);                \
                          }

/* order of output from S-box functions */
#define _beforeS0(f) f(0,a,b,c,d,e)
#define _afterS0(f)  f(1,b,e,c,a,d)
#define _afterS1(f)  f(2,c,b,a,e,d)
#define _afterS2(f)  f(3,a,e,b,d,c)
#define _afterS3(f)  f(4,e,b,d,c,a)
#define _afterS4(f)  f(5,b,a,e,c,d)
#define _afterS5(f)  f(6,a,c,b,e,d)
#define _afterS6(f)  f(7,a,c,d,b,e)
#define _afterS7(f)  f(8,d,e,b,a,c)

/* order of output from inverse S-box functions */
#define _beforeI7(f) f(8,a,b,c,d,e)
#define _afterI7(f)  f(7,d,a,b,e,c)
#define _afterI6(f)  f(6,a,b,c,e,d)
#define _afterI5(f)  f(5,b,d,e,c,a)
#define _afterI4(f)  f(4,b,c,e,a,d)
#define _afterI3(f)  f(3,a,b,e,c,d)
#define _afterI2(f)  f(2,b,d,e,c,a)
#define _afterI1(f)  f(1,a,b,c,e,d)
#define _afterI0(f)  f(0,a,d,b,e,c)

/* The instruction sequences for the S-box functions
 * come from Dag Arne Osvik's paper "Speeding up Serpent".
 */

#define _S0(i, r0, r1, r2, r3, r4) { \
   r3 ^= r0;   \
   r4 = r1;    \
   r1 &= r3;   \
   r4 ^= r2;   \
   r1 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r4;   \
   r4 ^= r3;   \
   r3 ^= r2;   \
   r2 |= r1;   \
   r2 ^= r4;   \
   r4 = ~r4;   \
   r4 |= r1;   \
   r1 ^= r3;   \
   r1 ^= r4;   \
   r3 |= r0;   \
   r1 ^= r3;   \
   r4 ^= r3;   \
}

#define _I0(i, r0, r1, r2, r3, r4) { \
   r2 = ~r2;   \
   r4 = r1;    \
   r1 |= r0;   \
   r4 = ~r4;   \
   r1 ^= r2;   \
   r2 |= r4;   \
   r1 ^= r3;   \
   r0 ^= r4;   \
   r2 ^= r0;   \
   r0 &= r3;   \
   r4 ^= r0;   \
   r0 |= r1;   \
   r0 ^= r2;   \
   r3 ^= r4;   \
   r2 ^= r1;   \
   r3 ^= r0;   \
   r3 ^= r1;   \
   r2 &= r3;   \
   r4 ^= r2;   \
}

#define _S1(i, r0, r1, r2, r3, r4) { \
   r0 = ~r0;   \
   r2 = ~r2;   \
   r4 = r0;    \
   r0 &= r1;   \
   r2 ^= r0;   \
   r0 |= r3;   \
   r3 ^= r2;   \
   r1 ^= r0;   \
   r0 ^= r4;   \
   r4 |= r1;   \
   r1 ^= r3;   \
   r2 |= r0;   \
   r2 &= r4;   \
   r0 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r0;   \
   r0 &= r2;   \
   r0 ^= r4;   \
}

#define _I1(i, r0, r1, r2, r3, r4) { \
   r4 = r1;    \
   r1 ^= r3;   \
   r3 &= r1;   \
   r4 ^= r2;   \
   r3 ^= r0;   \
   r0 |= r1;   \
   r2 ^= r3;   \
   r0 ^= r4;   \
   r0 |= r2;   \
   r1 ^= r3;   \
   r0 ^= r1;   \
   r1 |= r3;   \
   r1 ^= r0;   \
   r4 = ~r4;   \
   r4 ^= r1;   \
   r1 |= r0;   \
   r1 ^= r0;   \
   r1 |= r4;   \
   r3 ^= r1;   \
}

#define _S2(i, r0, r1, r2, r3, r4) { \
   r4 = r0;    \
   r0 &= r2;   \
   r0 ^= r3;   \
   r2 ^= r1;   \
   r2 ^= r0;   \
   r3 |= r4;   \
   r3 ^= r1;   \
   r4 ^= r2;   \
   r1 = r3;    \
   r3 |= r4;   \
   r3 ^= r0;   \
   r0 &= r1;   \
   r4 ^= r0;   \
   r1 ^= r3;   \
   r1 ^= r4;   \
   r4 = ~r4;   \
}

#define _I2(i, r0, r1, r2, r3, r4) { \
   r2 ^= r3;   \
   r3 ^= r0;   \
   r4 = r3;    \
   r3 &= r2;   \
   r3 ^= r1;   \
   r1 |= r2;   \
   r1 ^= r4;   \
   r4 &= r3;   \
   r2 ^= r3;   \
   r4 &= r0;   \
   r4 ^= r2;   \
   r2 &= r1;   \
   r2 |= r0;   \
   r3 = ~r3;   \
   r2 ^= r3;   \
   r0 ^= r3;   \
   r0 &= r1;   \
   r3 ^= r4;   \
   r3 ^= r0;   \
}

#define _S3(i, r0, r1, r2, r3, r4) { \
   r4 = r0;    \
   r0 |= r3;   \
   r3 ^= r1;   \
   r1 &= r4;   \
   r4 ^= r2;   \
   r2 ^= r3;   \
   r3 &= r0;   \
   r4 |= r1;   \
   r3 ^= r4;   \
   r0 ^= r1;   \
   r4 &= r0;   \
   r1 ^= r3;   \
   r4 ^= r2;   \
   r1 |= r0;   \
   r1 ^= r2;   \
   r0 ^= r3;   \
   r2 = r1;    \
   r1 |= r3;   \
   r1 ^= r0;   \
}

#define _I3(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r0;   \
   r0 &= r4;   \
   r4 ^= r3;   \
   r3 |= r1;   \
   r3 ^= r2;   \
   r0 ^= r4;   \
   r2 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r1;   \
   r4 ^= r2;   \
   r2 &= r3;   \
   r1 |= r3;   \
   r1 ^= r2;   \
   r4 ^= r0;   \
   r2 ^= r4;   \
}

#define _S4(i, r0, r1, r2, r3, r4) { \
   r1 ^= r3;   \
   r3 = ~r3;   \
   r2 ^= r3;   \
   r3 ^= r0;   \
   r4 = r1;    \
   r1 &= r3;   \
   r1 ^= r2;   \
   r4 ^= r3;   \
   r0 ^= r4;   \
   r2 &= r4;   \
   r2 ^= r0;   \
   r0 &= r1;   \
   r3 ^= r0;   \
   r4 |= r1;   \
   r4 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r2;   \
   r2 &= r3;   \
   r0 = ~r0;   \
   r4 ^= r2;   \
}

#define _I4(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 &= r3;   \
   r2 ^= r1;   \
   r1 |= r3;   \
   r1 &= r0;   \
   r4 ^= r2;   \
   r4 ^= r1;   \
   r1 &= r2;   \
   r0 = ~r0;   \
   r3 ^= r4;   \
   r1 ^= r3;   \
   r3 &= r0;   \
   r3 ^= r2;   \
   r0 ^= r1;   \
   r2 &= r0;   \
   r3 ^= r0;   \
   r2 ^= r4;   \
   r2 |= r3;   \
   r3 ^= r0;   \
   r2 ^= r1;   \
}

#define _S5(i, r0, r1, r2, r3, r4) { \
   r0 ^= r1;   \
   r1 ^= r3;   \
   r3 = ~r3;   \
   r4 = r1;    \
   r1 &= r0;   \
   r2 ^= r3;   \
   r1 ^= r2;   \
   r2 |= r4;   \
   r4 ^= r3;   \
   r3 &= r1;   \
   r3 ^= r0;   \
   r4 ^= r1;   \
   r4 ^= r2;   \
   r2 ^= r0;   \
   r0 &= r3;   \
   r2 = ~r2;   \
   r0 ^= r4;   \
   r4 |= r3;   \
   r2 ^= r4;   \
}

#define _I5(i, r0, r1, r2, r3, r4) { \
   r1 = ~r1;   \
   r4 = r3;    \
   r2 ^= r1;   \
   r3 |= r0;   \
   r3 ^= r2;   \
   r2 |= r1;   \
   r2 &= r0;   \
   r4 ^= r3;   \
   r2 ^= r4;   \
   r4 |= r0;   \
   r4 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r3;   \
   r4 ^= r2;   \
   r3 &= r4;   \
   r4 ^= r1;   \
   r3 ^= r0;   \
   r3 ^= r4;   \
   r4 = ~r4;   \
}

#define _S6(i, r0, r1, r2, r3, r4) { \
   r2 = ~r2;   \
   r4 = r3;    \
   r3 &= r0;   \
   r0 ^= r4;   \
   r3 ^= r2;   \
   r2 |= r4;   \
   r1 ^= r3;   \
   r2 ^= r0;   \
   r0 |= r1;   \
   r2 ^= r1;   \
   r4 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r2;   \
   r4 ^= r3;   \
   r4 ^= r0;   \
   r3 = ~r3;   \
   r2 &= r4;   \
   r2 ^= r3;   \
}

#define _I6(i, r0, r1, r2, r3, r4) { \
   r0 ^= r2;   \
   r4 = r2;    \
   r2 &= r0;   \
   r4 ^= r3;   \
   r2 = ~r2;   \
   r3 ^= r1;   \
   r2 ^= r3;   \
   r4 |= r0;   \
   r0 ^= r2;   \
   r3 ^= r4;   \
   r4 ^= r1;   \
   r1 &= r3;   \
   r1 ^= r0;   \
   r0 ^= r3;   \
   r0 |= r2;   \
   r3 ^= r1;   \
   r4 ^= r0;   \
}

#define _S7(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 &= r1;   \
   r2 ^= r3;   \
   r3 &= r1;   \
   r4 ^= r2;   \
   r2 ^= r1;   \
   r1 ^= r0;   \
   r0 |= r4;   \
   r0 ^= r2;   \
   r3 ^= r1;   \
   r2 ^= r3;   \
   r3 &= r0;   \
   r3 ^= r4;   \
   r4 ^= r2;   \
   r2 &= r0;   \
   r4 = ~r4;   \
   r2 ^= r4;   \
   r4 &= r0;   \
   r1 ^= r3;   \
   r4 ^= r1;   \
}

#define _I7(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 ^= r0;   \
   r0 &= r3;   \
   r2 = ~r2;   \
   r4 |= r3;   \
   r3 ^= r1;   \
   r1 |= r0;   \
   r0 ^= r2;   \
   r2 &= r4;   \
   r1 ^= r2;   \
   r2 ^= r0;   \
   r0 |= r2;   \
   r3 &= r4;   \
   r0 ^= r3;   \
   r4 ^= r1;   \
   r3 ^= r4;   \
   r4 |= r0;   \
   r3 ^= r2;   \
   r4 ^= r2;   \
}

/* key xor */
#define _KX(r, a, b, c, d, e) { \
   a ^= k[4 * r + 0];   \
   b ^= k[4 * r + 1];   \
   c ^= k[4 * r + 2];   \
   d ^= k[4 * r + 3];   \
}

#define _LK(r, a, b, c, d, e) { \
   a = k[(8-r)*4 + 0];  \
   b = k[(8-r)*4 + 1];  \
   c = k[(8-r)*4 + 2];  \
   d = k[(8-r)*4 + 3];  \
}

#define _SK(r, a, b, c, d, e) { \
   k[(8-r)*4 + 4] = a;  \
   k[(8-r)*4 + 5] = b;  \
   k[(8-r)*4 + 6] = c;  \
   k[(8-r)*4 + 7] = d;  \
}

static int _setup_key(const unsigned char *key, int keylen, int rounds, ulong32 *k)
{
   int i;
   ulong32 t;
   ulong32 k0[8] = { 0 }; /* zero-initialize */
   ulong32 a, b, c, d, e;

   for (i = 0; i < 8 && i < keylen/4; ++i) {
      LOAD32L(k0[i], key + i * 4);
   }
   if (keylen < 32) {
      k0[keylen/4] |= (ulong32)1 << ((keylen%4)*8);
    }

   t = k0[7];
   for (i = 0; i < 8; ++i) {
      k[i] = k0[i] = t = ROLc(k0[i] ^ k0[(i+3)%8] ^ k0[(i+5)%8] ^ t ^ 0x9e3779b9 ^ i, 11);
   }
   for (i = 8; i < 4*(rounds+1); ++i) {
      k[i] = t = ROLc(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
   }
   k -= 20;

   for (i = 0; i < rounds/8; i++) {
      _afterS2(_LK);  _afterS2(_S3);  _afterS3(_SK);
      _afterS1(_LK);  _afterS1(_S2);  _afterS2(_SK);
      _afterS0(_LK);  _afterS0(_S1);  _afterS1(_SK);
      _beforeS0(_LK); _beforeS0(_S0); _afterS0(_SK);
      k += 8*4;
      _afterS6(_LK); _afterS6(_S7); _afterS7(_SK);
      _afterS5(_LK); _afterS5(_S6); _afterS6(_SK);
      _afterS4(_LK); _afterS4(_S5); _afterS5(_SK);
      _afterS3(_LK); _afterS3(_S4); _afterS4(_SK);
   }
   _afterS2(_LK); _afterS2(_S3); _afterS3(_SK);

   return CRYPT_OK;
}

static int _enc_block(const unsigned char *in, unsigned char *out, const ulong32 *k)
{
   ulong32 a, b, c, d, e;
   unsigned int i = 1;

   LOAD32L(a, in + 0);
   LOAD32L(b, in + 4);
   LOAD32L(c, in + 8);
   LOAD32L(d, in + 12);

   do {
      _beforeS0(_KX); _beforeS0(_S0); _afterS0(_LT);
      _afterS0(_KX);  _afterS0(_S1);  _afterS1(_LT);
      _afterS1(_KX);  _afterS1(_S2);  _afterS2(_LT);
      _afterS2(_KX);  _afterS2(_S3);  _afterS3(_LT);
      _afterS3(_KX);  _afterS3(_S4);  _afterS4(_LT);
      _afterS4(_KX);  _afterS4(_S5);  _afterS5(_LT);
      _afterS5(_KX);  _afterS5(_S6);  _afterS6(_LT);
      _afterS6(_KX);  _afterS6(_S7);

      if (i == 4) break;

      ++i;
      c = b;
      b = e;
      e = d;
      d = a;
      a = e;
      k += 32;
      _beforeS0(_LT);
   } while (1);

   _afterS7(_KX);

   STORE32L(d, out + 0);
   STORE32L(e, out + 4);
   STORE32L(b, out + 8);
   STORE32L(a, out + 12);

   return CRYPT_OK;
}

static int _dec_block(const unsigned char *in, unsigned char *out, const ulong32 *k)
{
   ulong32 a, b, c, d, e;
   unsigned int i;

   LOAD32L(a, in + 0);
   LOAD32L(b, in + 4);
   LOAD32L(c, in + 8);
   LOAD32L(d, in + 12);
   e = 0; LTC_UNUSED_PARAM(e); /* avoid scan-build warning */
   i = 4;
   k += 96;

   _beforeI7(_KX);
   goto start;

   do {
      c = b;
      b = d;
      d = e;
      k -= 32;
      _beforeI7(_ILT);
start:
                      _beforeI7(_I7); _afterI7(_KX);
      _afterI7(_ILT); _afterI7(_I6);  _afterI6(_KX);
      _afterI6(_ILT); _afterI6(_I5);  _afterI5(_KX);
      _afterI5(_ILT); _afterI5(_I4);  _afterI4(_KX);
      _afterI4(_ILT); _afterI4(_I3);  _afterI3(_KX);
      _afterI3(_ILT); _afterI3(_I2);  _afterI2(_KX);
      _afterI2(_ILT); _afterI2(_I1);  _afterI1(_KX);
      _afterI1(_ILT); _afterI1(_I0);  _afterI0(_KX);
   } while (--i != 0);

   STORE32L(a, out + 0);
   STORE32L(d, out + 4);
   STORE32L(b, out + 8);
   STORE32L(e, out + 12);

   return CRYPT_OK;
}

int serpent_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   int err;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(skey != NULL);

   if (num_rounds != 0 && num_rounds != 32) return CRYPT_INVALID_ROUNDS;
   if (keylen != 16 && keylen != 24 && keylen != 32) return CRYPT_INVALID_KEYSIZE;

   err = _setup_key(key, keylen, 32, skey->serpent.k);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 14 + sizeof(int));
#endif
   return err;
}

int serpent_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{
   int err = _enc_block(pt, ct, skey->serpent.k);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 5 + sizeof(int));
#endif
   return err;
}

int serpent_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{
   int err = _dec_block(ct, pt, skey->serpent.k);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 5 + sizeof(int));
#endif
   return err;
}

void serpent_done(symmetric_key *skey)
{
   LTC_UNUSED_PARAM(skey);
}

int serpent_keysize(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);

   if (*keysize >= 32) { *keysize = 32; }
   else if (*keysize >= 24) { *keysize = 24; }
   else if (*keysize >= 16) { *keysize = 16; }
   else return CRYPT_INVALID_KEYSIZE;
   return CRYPT_OK;
}

int serpent_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
      unsigned char key[32];
      int keylen;
      unsigned char pt[16], ct[16];
   } tests[] = {
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xA2,0x23,0xAA,0x12,0x88,0x46,0x3C,0x0E,0x2B,0xE3,0x8E,0xBD,0x82,0x56,0x16,0xC0}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xEA,0xE1,0xD4,0x05,0x57,0x01,0x74,0xDF,0x7D,0xF2,0xF9,0x96,0x6D,0x50,0x91,0x59}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x65,0xF3,0x76,0x84,0x47,0x1E,0x92,0x1D,0xC8,0xA3,0x0F,0x45,0xB4,0x3C,0x44,0x99}
      },
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x9E,0x27,0x4E,0xAD,0x9B,0x73,0x7B,0xB2,0x1E,0xFC,0xFC,0xA5,0x48,0x60,0x26,0x89}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x92,0xFC,0x8E,0x51,0x03,0x99,0xE4,0x6A,0x04,0x1B,0xF3,0x65,0xE7,0xB3,0xAE,0x82}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x5E,0x0D,0xA3,0x86,0xC4,0x6A,0xD4,0x93,0xDE,0xA2,0x03,0xFD,0xC6,0xF5,0x7D,0x70}
      },
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x26,0x4E,0x54,0x81,0xEF,0xF4,0x2A,0x46,0x06,0xAB,0xDA,0x06,0xC0,0xBF,0xDA,0x3D}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x4A,0x23,0x1B,0x3B,0xC7,0x27,0x99,0x34,0x07,0xAC,0x6E,0xC8,0x35,0x0E,0x85,0x24}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xE0,0x32,0x69,0xF9,0xE9,0xFD,0x85,0x3C,0x7D,0x81,0x56,0xDF,0x14,0xB9,0x8D,0x56}
      }
   };

   unsigned char buf[2][16];
   symmetric_key key;
   int err, x;

   for (x = 0; x < (int)(sizeof(tests)/sizeof(tests[0])); x++) {
      if ((err = serpent_setup(tests[x].key, tests[x].keylen, 0, &key)) != CRYPT_OK) {
        return err;
      }
      if ((err = serpent_ecb_encrypt(tests[x].pt, buf[0], &key)) != CRYPT_OK) {
        return err;
      }
      if (compare_testvector(buf[0], 16, tests[x].ct, 16, "SERPENT Encrypt", x)) {
        return CRYPT_FAIL_TESTVECTOR;
      }
      if ((err = serpent_ecb_decrypt(tests[x].ct, buf[1], &key)) != CRYPT_OK) {
        return err;
      }
      if (compare_testvector(buf[1], 16, tests[x].pt, 16, "SERPENT Decrypt", x)) {
        return CRYPT_FAIL_TESTVECTOR;
      }
   }

   return CRYPT_OK;
#endif
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
