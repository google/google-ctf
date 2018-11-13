/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/******************************************************************************
 * This Rabbit C source code was morphed fm the EU eSTREAM ECRYPT submission
 * and should run on any conforming C implementation (C90 or later).
 *
 * This implementation supports any key length up to 128 bits (16 bytes) and
 * works in increments of 8-bit bytes.  Keys must be submitted as whole bytes
 * and shorter keys will be right-null-padded to 16 bytes.  Likewise, an iv
 * may be any length up to 8 bytes and will be padded out to 8 bytes.
 *
 * The eSTREAM submission was rather picky about the calling sequence of
 * ECRYPT_process_blocks() and ECRYPT_process_bytes().  That version allowed
 * calling ECRYPT_process_blocks() multiple times for a multiple of whole
 * 16-byte blocks, but once ECRYPT_process_bytes() was called. no more calls
 * were supported correctly.  This implementation handles the keystream
 * differently and rabbit_crypt() may be called as many times as desired,
 * crypting any number of bytes each time.
 *
 *   http://www.ecrypt.eu.org/stream/e2-rabbit.html
 *
 * NB: One of the test vectors distributed by the eSTREAM site in the file
 *     "rabbit_p3source.zip" is in error.  Referring to "test-vectors.txt"
 *     in that ZIP file, the 3rd line in "out1" should be
 *     "96 D6 73 16 88 D1 68 DA 51 D4 0C 70 C3 A1 16 F4".
 *
 * Here is the original legal notice accompanying the Rabbit submission
 * to the EU eSTREAM competition.
 *---------------------------------------------------------------------------
 * Copyright (C) Cryptico A/S. All rights reserved.
 *
 * YOU SHOULD CAREFULLY READ THIS LEGAL NOTICE BEFORE USING THIS SOFTWARE.
 *
 * This software is developed by Cryptico A/S and/or its suppliers.
 * All title and intellectual property rights in and to the software,
 * including but not limited to patent rights and copyrights, are owned
 * by Cryptico A/S and/or its suppliers.
 *
 * The software may be used solely for non-commercial purposes
 * without the prior written consent of Cryptico A/S. For further
 * information on licensing terms and conditions please contact
 * Cryptico A/S at info@cryptico.com
 *
 * Cryptico, CryptiCore, the Cryptico logo and "Re-thinking encryption"
 * are either trademarks or registered trademarks of Cryptico A/S.
 *
 * Cryptico A/S shall not in any way be liable for any use of this
 * software. The software is provided "as is" without any express or
 * implied warranty.
 *---------------------------------------------------------------------------
 * On October 6, 2008, Rabbit was "released into the public domain and
 * may be used freely for any purpose."
 *   http://www.ecrypt.eu.org/stream/rabbitpf.html
 *   https://web.archive.org/web/20090630021733/http://www.ecrypt.eu.org/stream/phorum/read.php?1,1244
 ******************************************************************************/


#include "tomcrypt_private.h"

#ifdef LTC_RABBIT

/* local/private prototypes  (NB: rabbit_ctx and rabbit_state are different)  */
static LTC_INLINE ulong32 _rabbit_g_func(ulong32 x);
static LTC_INLINE void _rabbit_next_state(rabbit_ctx *p_instance);
static LTC_INLINE void _rabbit_gen_1_block(rabbit_state* st, unsigned char *out);

/* -------------------------------------------------------------------------- */

/* Square a 32-bit unsigned integer to obtain the 64-bit result and return */
/* the upper 32 bits XOR the lower 32 bits */
static LTC_INLINE ulong32 _rabbit_g_func(ulong32 x)
{
   ulong32 a, b, h, l;

   /* Construct high and low argument for squaring */
   a = x &  0xFFFF;
   b = x >> 16;

   /* Calculate high and low result of squaring */
   h = ((((ulong32)(a*a)>>17) + (ulong32)(a*b))>>15) + b*b;
   l = x * x;

   /* Return high XOR low */
   return (ulong32)(h^l);
}

/* -------------------------------------------------------------------------- */

/* Calculate the next internal state */
static LTC_INLINE void _rabbit_next_state(rabbit_ctx *p_instance)
{
   ulong32 g[8], c_old[8], i;

   /* Save old counter values */
   for (i=0; i<8; i++) {
      c_old[i] = p_instance->c[i];
   }

   /* Calculate new counter values */
   p_instance->c[0] = (ulong32)(p_instance->c[0] + 0x4D34D34D + p_instance->carry);
   p_instance->c[1] = (ulong32)(p_instance->c[1] + 0xD34D34D3 + (p_instance->c[0] < c_old[0]));
   p_instance->c[2] = (ulong32)(p_instance->c[2] + 0x34D34D34 + (p_instance->c[1] < c_old[1]));
   p_instance->c[3] = (ulong32)(p_instance->c[3] + 0x4D34D34D + (p_instance->c[2] < c_old[2]));
   p_instance->c[4] = (ulong32)(p_instance->c[4] + 0xD34D34D3 + (p_instance->c[3] < c_old[3]));
   p_instance->c[5] = (ulong32)(p_instance->c[5] + 0x34D34D34 + (p_instance->c[4] < c_old[4]));
   p_instance->c[6] = (ulong32)(p_instance->c[6] + 0x4D34D34D + (p_instance->c[5] < c_old[5]));
   p_instance->c[7] = (ulong32)(p_instance->c[7] + 0xD34D34D3 + (p_instance->c[6] < c_old[6]));
   p_instance->carry = (p_instance->c[7] < c_old[7]);

   /* Calculate the g-values */
   for (i=0;i<8;i++) {
      g[i] = _rabbit_g_func((ulong32)(p_instance->x[i] + p_instance->c[i]));
   }

   /* Calculate new state values */
   p_instance->x[0] = (ulong32)(g[0] + ROLc(g[7],16) + ROLc(g[6], 16));
   p_instance->x[1] = (ulong32)(g[1] + ROLc(g[0], 8) + g[7]);
   p_instance->x[2] = (ulong32)(g[2] + ROLc(g[1],16) + ROLc(g[0], 16));
   p_instance->x[3] = (ulong32)(g[3] + ROLc(g[2], 8) + g[1]);
   p_instance->x[4] = (ulong32)(g[4] + ROLc(g[3],16) + ROLc(g[2], 16));
   p_instance->x[5] = (ulong32)(g[5] + ROLc(g[4], 8) + g[3]);
   p_instance->x[6] = (ulong32)(g[6] + ROLc(g[5],16) + ROLc(g[4], 16));
   p_instance->x[7] = (ulong32)(g[7] + ROLc(g[6], 8) + g[5]);
}

/* ------------------------------------------------------------------------- */

static LTC_INLINE void _rabbit_gen_1_block(rabbit_state* st, unsigned char *out)
{
    ulong32 *ptr;

    /* Iterate the work context once */
    _rabbit_next_state(&(st->work_ctx));

    /* Generate 16 bytes of pseudo-random data */
    ptr = (ulong32*)&(st->work_ctx.x);
    STORE32L((ptr[0] ^ (ptr[5]>>16) ^ (ulong32)(ptr[3]<<16)), out+ 0);
    STORE32L((ptr[2] ^ (ptr[7]>>16) ^ (ulong32)(ptr[5]<<16)), out+ 4);
    STORE32L((ptr[4] ^ (ptr[1]>>16) ^ (ulong32)(ptr[7]<<16)), out+ 8);
    STORE32L((ptr[6] ^ (ptr[3]>>16) ^ (ulong32)(ptr[1]<<16)), out+12);
}

/* -------------------------------------------------------------------------- */

/* Key setup */
int rabbit_setup(rabbit_state* st, const unsigned char *key, unsigned long keylen)
{
   ulong32 k0, k1, k2, k3, i;
   unsigned char  tmpkey[16] = {0};

   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(keylen <= 16);

   /* init state */
   XMEMSET(st, 0, sizeof(rabbit_state));

   /* pad key in tmpkey */
   XMEMCPY(tmpkey, key, keylen);

   /* Generate four subkeys */
   LOAD32L(k0, tmpkey+ 0);
   LOAD32L(k1, tmpkey+ 4);
   LOAD32L(k2, tmpkey+ 8);
   LOAD32L(k3, tmpkey+12);

#ifdef LTC_CLEAN_STACK
   /* done with tmpkey, wipe it */
   zeromem(tmpkey, sizeof(tmpkey));
#endif

   /* Generate initial state variables */
   st->master_ctx.x[0] = k0;
   st->master_ctx.x[2] = k1;
   st->master_ctx.x[4] = k2;
   st->master_ctx.x[6] = k3;
   st->master_ctx.x[1] = (ulong32)(k3<<16) | (k2>>16);
   st->master_ctx.x[3] = (ulong32)(k0<<16) | (k3>>16);
   st->master_ctx.x[5] = (ulong32)(k1<<16) | (k0>>16);
   st->master_ctx.x[7] = (ulong32)(k2<<16) | (k1>>16);

   /* Generate initial counter values */
   st->master_ctx.c[0] = ROLc(k2, 16);
   st->master_ctx.c[2] = ROLc(k3, 16);
   st->master_ctx.c[4] = ROLc(k0, 16);
   st->master_ctx.c[6] = ROLc(k1, 16);
   st->master_ctx.c[1] = (k0&0xFFFF0000) | (k1&0xFFFF);
   st->master_ctx.c[3] = (k1&0xFFFF0000) | (k2&0xFFFF);
   st->master_ctx.c[5] = (k2&0xFFFF0000) | (k3&0xFFFF);
   st->master_ctx.c[7] = (k3&0xFFFF0000) | (k0&0xFFFF);

   /* Clear carry bit */
   st->master_ctx.carry = 0;

   /* Iterate the master context four times */
   for (i=0; i<4; i++) {
      _rabbit_next_state(&(st->master_ctx));
   }

   /* Modify the counters */
   for (i=0; i<8; i++) {
      st->master_ctx.c[i] ^= st->master_ctx.x[(i+4)&0x7];
   }

   /* Copy master instance to work instance */
   for (i=0; i<8; i++) {
      st->work_ctx.x[i] = st->master_ctx.x[i];
      st->work_ctx.c[i] = st->master_ctx.c[i];
   }
   st->work_ctx.carry = st->master_ctx.carry;
   /* ...and prepare block for crypt() */
   XMEMSET(&(st->block), 0, sizeof(st->block));
   st->unused = 0;

   return CRYPT_OK;
}

/* -------------------------------------------------------------------------- */

/* IV setup */
int rabbit_setiv(rabbit_state* st, const unsigned char *iv, unsigned long ivlen)
{
   ulong32 i0, i1, i2, i3, i;
   unsigned char  tmpiv[8] = {0};

   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(iv != NULL || ivlen == 0);
   LTC_ARGCHK(ivlen <= 8);

   /* pad iv in tmpiv */
   if (iv && ivlen > 0) XMEMCPY(tmpiv, iv, ivlen);

   /* Generate four subvectors */
   LOAD32L(i0, tmpiv+0);
   LOAD32L(i2, tmpiv+4);
   i1 = (i0>>16) | (i2&0xFFFF0000);
   i3 = (i2<<16) | (i0&0x0000FFFF);

   /* Modify counter values */
   st->work_ctx.c[0] = st->master_ctx.c[0] ^ i0;
   st->work_ctx.c[1] = st->master_ctx.c[1] ^ i1;
   st->work_ctx.c[2] = st->master_ctx.c[2] ^ i2;
   st->work_ctx.c[3] = st->master_ctx.c[3] ^ i3;
   st->work_ctx.c[4] = st->master_ctx.c[4] ^ i0;
   st->work_ctx.c[5] = st->master_ctx.c[5] ^ i1;
   st->work_ctx.c[6] = st->master_ctx.c[6] ^ i2;
   st->work_ctx.c[7] = st->master_ctx.c[7] ^ i3;

   /* Copy state variables */
   for (i=0; i<8; i++) {
      st->work_ctx.x[i] = st->master_ctx.x[i];
   }
   st->work_ctx.carry = st->master_ctx.carry;

   /* Iterate the work context four times */
   for (i=0; i<4; i++) {
      _rabbit_next_state(&(st->work_ctx));
   }

   /* reset keystream buffer and unused count */
   XMEMSET(&(st->block), 0, sizeof(st->block));
   st->unused = 0;

   return CRYPT_OK;
}

/* ------------------------------------------------------------------------- */

/* Crypt a chunk of any size (encrypt/decrypt) */
int rabbit_crypt(rabbit_state* st, const unsigned char *in, unsigned long inlen, unsigned char *out)
{
   unsigned char buf[16];
   unsigned long i, j;

   if (inlen == 0) return CRYPT_OK; /* nothing to do */

   LTC_ARGCHK(st        != NULL);
   LTC_ARGCHK(in        != NULL);
   LTC_ARGCHK(out       != NULL);

   if (st->unused > 0) {
      j = MIN(st->unused, inlen);
      for (i = 0; i < j; ++i, st->unused--) out[i] = in[i] ^ st->block[16 - st->unused];
      inlen -= j;
      if (inlen == 0) return CRYPT_OK;
      out += j;
      in  += j;
   }
   for (;;) {
     /* gen a block for buf */
     _rabbit_gen_1_block(st, buf);
     if (inlen <= 16) {
       /* XOR and send to out */
       for (i = 0; i < inlen; ++i) out[i] = in[i] ^ buf[i];
       st->unused = 16 - inlen;
       /* copy remainder to block */
       for (i = inlen; i < 16; ++i) st->block[i] = buf[i];
       return CRYPT_OK;
     }
     /* XOR entire buf and send to out */
     for (i = 0; i < 16; ++i) out[i] = in[i] ^ buf[i];
     inlen -= 16;
     out += 16;
     in  += 16;
   }
}

/* ------------------------------------------------------------------------- */

int rabbit_keystream(rabbit_state *st, unsigned char *out, unsigned long outlen)
{
   if (outlen == 0) return CRYPT_OK; /* nothing to do */

   LTC_ARGCHK(out != NULL);

   XMEMSET(out, 0, outlen);
   return rabbit_crypt(st, out, outlen, out);
}

/* -------------------------------------------------------------------------- */

int rabbit_done(rabbit_state *st)
{
   LTC_ARGCHK(st != NULL);

   zeromem(st, sizeof(rabbit_state));
   return CRYPT_OK;
}

/* -------------------------------------------------------------------------- */

int rabbit_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   rabbit_state st;
   int err;
   unsigned char out[1000] = { 0 };
   {
      /* all 3 tests use key and iv fm set 6, vector 3, the last vector in:
         http://www.ecrypt.eu.org/stream/svn/viewcvs.cgi/ecrypt/trunk/submissions/rabbit/verified.test-vectors?rev=210&view=log
      */

      /* --- Test 1 (generate whole blocks) --------------------------------- */

      {
         unsigned char k[]  = { 0x0F, 0x62, 0xB5, 0x08, 0x5B, 0xAE, 0x01, 0x54,
                                0xA7, 0xFA, 0x4D, 0xA0, 0xF3, 0x46, 0x99, 0xEC };
         unsigned char iv[] = { 0x28, 0x8F, 0xF6, 0x5D, 0xC4, 0x2B, 0x92, 0xF9 };
         char pt[64]        = { 0 };
         unsigned char ct[] = { 0x61, 0x3C, 0xB0, 0xBA, 0x96, 0xAF, 0xF6, 0xCA,
                                0xCF, 0x2A, 0x45, 0x9A, 0x10, 0x2A, 0x7F, 0x78,
                                0xCA, 0x98, 0x5C, 0xF8, 0xFD, 0xD1, 0x47, 0x40,
                                0x18, 0x75, 0x8E, 0x36, 0xAE, 0x99, 0x23, 0xF5,
                                0x19, 0xD1, 0x3D, 0x71, 0x8D, 0xAF, 0x8D, 0x7C,
                                0x0C, 0x10, 0x9B, 0x79, 0xD5, 0x74, 0x94, 0x39,
                                0xB7, 0xEF, 0xA4, 0xC4, 0xC9, 0xC8, 0xD2, 0x9D,
                                0xC5, 0xB3, 0x88, 0x83, 0x14, 0xA6, 0x81, 0x6F };
         unsigned long ptlen = sizeof(pt);

         /* crypt 64 nulls */
         if ((err = rabbit_setup(&st, k, sizeof(k)))                   != CRYPT_OK) return err;
         if ((err = rabbit_setiv(&st, iv, sizeof(iv)))                 != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt, ptlen, out)) != CRYPT_OK) return err;
         if (compare_testvector(out, ptlen, ct, ptlen, "RABBIT-TV1", 1))   return CRYPT_FAIL_TESTVECTOR;
      }

      /* --- Test 2 (generate unusual number of bytes each time) ------------ */

      {
         unsigned char k[]  = { 0x0F, 0x62, 0xB5, 0x08, 0x5B, 0xAE, 0x01, 0x54,
                                0xA7, 0xFA, 0x4D, 0xA0, 0xF3, 0x46, 0x99, 0xEC };
         unsigned char iv[] = { 0x28, 0x8F, 0xF6, 0x5D, 0xC4, 0x2B, 0x92, 0xF9 };
         char          pt[39] = { 0 };
         unsigned char ct[] = { 0x61, 0x3C, 0xB0, 0xBA,   0x96, 0xAF, 0xF6, 0xCA,
                                0xCF, 0x2A, 0x45, 0x9A,   0x10, 0x2A, 0x7F, 0x78,
                                0xCA, 0x98, 0x5C, 0xF8,   0xFD, 0xD1, 0x47, 0x40,
                                0x18, 0x75, 0x8E, 0x36,   0xAE, 0x99, 0x23, 0xF5,
                                0x19, 0xD1, 0x3D, 0x71,   0x8D, 0xAF, 0x8D };
         unsigned long ptlen = sizeof(pt);

         /* crypt piece by piece (hit at least one 16-byte boundary) */
         if ((err = rabbit_setup(&st, k, sizeof(k)))                          != CRYPT_OK) return err;
         if ((err = rabbit_setiv(&st, iv, sizeof(iv)))                        != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt,       5, out))      != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt +  5, 11, out +  5)) != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt + 16, 14, out + 16)) != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt + 30,  2, out + 30)) != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt + 32,  7, out + 32)) != CRYPT_OK) return err;
         if (compare_testvector(out, ptlen, ct, ptlen, "RABBIT-TV2", 1))   return CRYPT_FAIL_TESTVECTOR;
      }

      /* --- Test 3 (use non-null data) ------------------------------------- */

      {
         unsigned char k[]  = { 0x0F, 0x62, 0xB5, 0x08, 0x5B, 0xAE, 0x01, 0x54,
                                0xA7, 0xFA, 0x4D, 0xA0, 0xF3, 0x46, 0x99, 0xEC };
         unsigned char iv[] = { 0x28, 0x8F, 0xF6, 0x5D, 0xC4, 0x2B, 0x92, 0xF9 };
         char          pt[] = "Kilroy was here, there, and everywhere!";
         unsigned char ct[] = { 0x2a, 0x55, 0xdc, 0xc8,   0xf9, 0xd6, 0xd6, 0xbd,
                                0xae, 0x59, 0x65, 0xf2,   0x75, 0x58, 0x1a, 0x54,
                                0xea, 0xec, 0x34, 0x9d,   0x8f, 0xb4, 0x6b, 0x60,
                                0x79, 0x1b, 0xea, 0x16,   0xcb, 0xef, 0x46, 0x87,
                                0x60, 0xa6, 0x55, 0x14,   0xff, 0xca, 0xac };
         unsigned long ptlen = strlen(pt);
         unsigned char out2[1000] = { 0 };
         unsigned char nulls[1000] = { 0 };

         /* crypt piece by piece */
         if ((err = rabbit_setup(&st, k, sizeof(k)))                          != CRYPT_OK) return err;
         if ((err = rabbit_setiv(&st, iv, sizeof(iv)))                        != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt,       5, out))      != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt +  5, 29, out +  5)) != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, (unsigned char*)pt + 34,  5, out + 34)) != CRYPT_OK) return err;
         if (compare_testvector(out, ptlen, ct, ptlen, "RABBIT-TV3", 1))   return CRYPT_FAIL_TESTVECTOR;

      /* --- Test 4 (crypt in a single call) ------------------------------------ */

         if ((err = rabbit_memory(k, sizeof(k), iv, sizeof(iv),
                                   (unsigned char*)pt, sizeof(pt), out))      != CRYPT_OK) return err;
         if (compare_testvector(out, ptlen, ct, ptlen, "RABBIT-TV4", 1))   return CRYPT_FAIL_TESTVECTOR;
         /* use 'out' (ciphertext) in the next decryption test */

      /* --- Test 5 (decrypt ciphertext) ------------------------------------ */

         /* decrypt ct (out) and compare with pt (start with only setiv() to reset) */
         if ((err = rabbit_setiv(&st, iv, sizeof(iv)))                        != CRYPT_OK) return err;
         if ((err = rabbit_crypt(&st, out, ptlen, out2))                      != CRYPT_OK) return err;
         if (compare_testvector(out2, ptlen, pt, ptlen, "RABBIT-TV5", 1))  return CRYPT_FAIL_TESTVECTOR;

      /* --- Test 6 (wipe state, incl key) ---------------------------------- */

         if ((err = rabbit_done(&st))                      != CRYPT_OK) return err;
         if (compare_testvector(&st, sizeof(st), nulls, sizeof(st), "RABBIT-TV6", 1))  return CRYPT_FAIL_TESTVECTOR;

      }

      return CRYPT_OK;
   }
#endif
}

/* -------------------------------------------------------------------------- */

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
