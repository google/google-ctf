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
 @file sober128_stream.c
 Implementation of SOBER-128 by Tom St Denis.
 Based on s128fast.c reference code supplied by Greg Rose of QUALCOMM.
*/

#ifdef LTC_SOBER128

#define __LTC_SOBER128TAB_C__
#include "sober128tab.c"

/* don't change these... */
#define N                        17
#define INITKONST        0x6996c53a /* value of KONST to use during key loading */
#define KEYP                     15 /* where to insert key words */
#define FOLDP                     4 /* where to insert non-linear feedback */

static ulong32 BYTE2WORD(const unsigned char *b)
{
   ulong32 t;
   LOAD32L(t, b);
   return t;
}

static void XORWORD(ulong32 w, const unsigned char *in, unsigned char *out)
{
   ulong32 t;
   LOAD32L(t, in);
   t ^= w;
   STORE32L(t, out);
}

/* give correct offset for the current position of the register,
 * where logically R[0] is at position "zero".
 */
#define OFF(zero, i) (((zero)+(i)) % N)

/* step the LFSR */
/* After stepping, "zero" moves right one place */
#define STEP(R,z) \
    R[OFF(z,0)] = R[OFF(z,15)] ^ R[OFF(z,4)] ^ (R[OFF(z,0)] << 8) ^ Multab[(R[OFF(z,0)] >> 24) & 0xFF];

static void cycle(ulong32 *R)
{
    ulong32 t;
    int     i;

    STEP(R,0);
    t = R[0];
    for (i = 1; i < N; ++i) {
        R[i-1] = R[i];
    }
    R[N-1] = t;
}

/* Return a non-linear function of some parts of the register.
 */
#define NLFUNC(st,z) \
{ \
    t = st->R[OFF(z,0)] + st->R[OFF(z,16)]; \
    t ^= Sbox[(t >> 24) & 0xFF]; \
    t = RORc(t, 8); \
    t = ((t + st->R[OFF(z,1)]) ^ st->konst) + st->R[OFF(z,6)]; \
    t ^= Sbox[(t >> 24) & 0xFF]; \
    t = t + st->R[OFF(z,13)]; \
}

static ulong32 nltap(const sober128_state *st)
{
    ulong32 t;
    NLFUNC(st, 0);
    return t;
}

/* Save the current register state
 */
static void s128_savestate(sober128_state *st)
{
    int i;
    for (i = 0; i < N; ++i) {
        st->initR[i] = st->R[i];
    }
}

/* initialise to previously saved register state
 */
static void s128_reloadstate(sober128_state *st)
{
    int i;

    for (i = 0; i < N; ++i) {
        st->R[i] = st->initR[i];
    }
}

/* Initialise "konst"
 */
static void s128_genkonst(sober128_state *st)
{
    ulong32 newkonst;

    do {
       cycle(st->R);
       newkonst = nltap(st);
    } while ((newkonst & 0xFF000000) == 0);
    st->konst = newkonst;
}

/* Load key material into the register
 */
#define ADDKEY(k) \
   st->R[KEYP] += (k);

#define XORNL(nl) \
   st->R[FOLDP] ^= (nl);

/* nonlinear diffusion of register for key */
#define DROUND(z) STEP(st->R,z); NLFUNC(st,(z+1)); st->R[OFF((z+1),FOLDP)] ^= t;
static void s128_diffuse(sober128_state *st)
{
    ulong32 t;
    /* relies on FOLD == N == 17! */
    DROUND(0);
    DROUND(1);
    DROUND(2);
    DROUND(3);
    DROUND(4);
    DROUND(5);
    DROUND(6);
    DROUND(7);
    DROUND(8);
    DROUND(9);
    DROUND(10);
    DROUND(11);
    DROUND(12);
    DROUND(13);
    DROUND(14);
    DROUND(15);
    DROUND(16);
}

/**
   Initialize an Sober128 context (only the key)
   @param st        [out] The destination of the Sober128 state
   @param key       The secret key
   @param keylen    The length of the secret key (octets)
   @return CRYPT_OK if successful
*/
int sober128_stream_setup(sober128_state *st, const unsigned char *key, unsigned long keylen)
{
   ulong32 i, k;

   LTC_ARGCHK(st  != NULL);
   LTC_ARGCHK(key != NULL);
   LTC_ARGCHK(keylen > 0);

   /* keylen must be multiple of 4 bytes */
   if ((keylen & 3) != 0) {
      return CRYPT_INVALID_KEYSIZE;
   }

   /* Register initialised to Fibonacci numbers */
   st->R[0] = 1;
   st->R[1] = 1;
   for (i = 2; i < N; ++i) {
      st->R[i] = st->R[i-1] + st->R[i-2];
   }
   st->konst = INITKONST;

   for (i = 0; i < keylen; i += 4) {
      k = BYTE2WORD((unsigned char *)&key[i]);
      ADDKEY(k);
      cycle(st->R);
      XORNL(nltap(st));
   }

   /* also fold in the length of the key */
   ADDKEY(keylen);

   /* now diffuse */
   s128_diffuse(st);
   s128_genkonst(st);
   s128_savestate(st);
   st->nbuf = 0;

   return CRYPT_OK;
}

/**
  Set IV to the Sober128 state
  @param st      The Sober12820 state
  @param iv      The IV data to add
  @param ivlen   The length of the IV (must be 12)
  @return CRYPT_OK on success
 */
int sober128_stream_setiv(sober128_state *st, const unsigned char *iv, unsigned long ivlen)
{
   ulong32 i, k;

   LTC_ARGCHK(st != NULL);
   LTC_ARGCHK(iv != NULL);
   LTC_ARGCHK(ivlen > 0);

   /* ok we are adding an IV then... */
   s128_reloadstate(st);

   /* ivlen must be multiple of 4 bytes */
   if ((ivlen & 3) != 0) {
      return CRYPT_INVALID_KEYSIZE;
   }

   for (i = 0; i < ivlen; i += 4) {
      k = BYTE2WORD((unsigned char *)&iv[i]);
      ADDKEY(k);
      cycle(st->R);
      XORNL(nltap(st));
   }

   /* also fold in the length of the key */
   ADDKEY(ivlen);

   /* now diffuse */
   s128_diffuse(st);
   st->nbuf = 0;

   return CRYPT_OK;
}

/* XOR pseudo-random bytes into buffer
 */
#define SROUND(z) STEP(st->R,z); NLFUNC(st,(z+1)); XORWORD(t, in+(z*4), out+(z*4));

/**
   Encrypt (or decrypt) bytes of ciphertext (or plaintext) with Sober128
   @param st      The Sober128 state
   @param in      The plaintext (or ciphertext)
   @param inlen   The length of the input (octets)
   @param out     [out] The ciphertext (or plaintext), length inlen
   @return CRYPT_OK if successful
*/
int sober128_stream_crypt(sober128_state *st, const unsigned char *in, unsigned long inlen, unsigned char *out)
{
   ulong32 t;

   if (inlen == 0) return CRYPT_OK; /* nothing to do */
   LTC_ARGCHK(out != NULL);
   LTC_ARGCHK(st  != NULL);

   /* handle any previously buffered bytes */
   while (st->nbuf != 0 && inlen != 0) {
      *out++ = *in++ ^ (unsigned char)(st->sbuf & 0xFF);
      st->sbuf >>= 8;
      st->nbuf -= 8;
      --inlen;
   }

#ifndef LTC_SMALL_CODE
   /* do lots at a time, if there's enough to do */
   while (inlen >= N*4) {
      SROUND(0);
      SROUND(1);
      SROUND(2);
      SROUND(3);
      SROUND(4);
      SROUND(5);
      SROUND(6);
      SROUND(7);
      SROUND(8);
      SROUND(9);
      SROUND(10);
      SROUND(11);
      SROUND(12);
      SROUND(13);
      SROUND(14);
      SROUND(15);
      SROUND(16);
      out    += 4*N;
      in     += 4*N;
      inlen  -= 4*N;
   }
#endif

   /* do small or odd size buffers the slow way */
   while (4 <= inlen) {
      cycle(st->R);
      t = nltap(st);
      XORWORD(t, in, out);
      out    += 4;
      in     += 4;
      inlen  -= 4;
   }

   /* handle any trailing bytes */
   if (inlen != 0) {
      cycle(st->R);
      st->sbuf = nltap(st);
      st->nbuf = 32;
      while (st->nbuf != 0 && inlen != 0) {
          *out++ = *in++ ^ (unsigned char)(st->sbuf & 0xFF);
          st->sbuf >>= 8;
          st->nbuf -= 8;
          --inlen;
      }
   }

   return CRYPT_OK;
}

int sober128_stream_keystream(sober128_state *st, unsigned char *out, unsigned long outlen)
{
   if (outlen == 0) return CRYPT_OK; /* nothing to do */
   LTC_ARGCHK(out != NULL);
   XMEMSET(out, 0, outlen);
   return sober128_stream_crypt(st, out, outlen, out);
}

/**
  Terminate and clear Sober128 state
  @param st      The Sober128 state
  @return CRYPT_OK on success
*/
int sober128_stream_done(sober128_state *st)
{
   LTC_ARGCHK(st != NULL);
   XMEMSET(st, 0, sizeof(sober128_state));
   return CRYPT_OK;
}

#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
