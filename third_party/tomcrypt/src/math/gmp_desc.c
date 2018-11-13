/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

#define DESC_DEF_ONLY
#include "tomcrypt_private.h"

#ifdef GMP_DESC

#include <stdio.h>
#include <gmp.h>

static int init(void **a)
{
   LTC_ARGCHK(a != NULL);

   *a = XCALLOC(1, sizeof(__mpz_struct));
   if (*a == NULL) {
      return CRYPT_MEM;
   }
   mpz_init(((__mpz_struct *)*a));
   return CRYPT_OK;
}

static void deinit(void *a)
{
   LTC_ARGCHKVD(a != NULL);
   mpz_clear(a);
   XFREE(a);
}

static int neg(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_neg(b, a);
   return CRYPT_OK;
}

static int copy(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_set(b, a);
   return CRYPT_OK;
}

static int init_copy(void **a, void *b)
{
   if (init(a) != CRYPT_OK) {
      return CRYPT_MEM;
   }
   return copy(b, *a);
}

/* ---- trivial ---- */
static int set_int(void *a, ltc_mp_digit b)
{
   LTC_ARGCHK(a != NULL);
   mpz_set_ui(((__mpz_struct *)a), b);
   return CRYPT_OK;
}

static unsigned long get_int(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mpz_get_ui(a);
}

static ltc_mp_digit get_digit(void *a, int n)
{
   LTC_ARGCHK(a != NULL);
   return mpz_getlimbn(a, n);
}

static int get_digit_count(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mpz_size(a);
}

static int compare(void *a, void *b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   ret = mpz_cmp(a, b);
   if (ret < 0) {
      return LTC_MP_LT;
   } else if (ret > 0) {
      return LTC_MP_GT;
   } else {
      return LTC_MP_EQ;
   }
}

static int compare_d(void *a, ltc_mp_digit b)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   ret = mpz_cmp_ui(((__mpz_struct *)a), b);
   if (ret < 0) {
      return LTC_MP_LT;
   } else if (ret > 0) {
      return LTC_MP_GT;
   } else {
      return LTC_MP_EQ;
   }
}

static int count_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mpz_sizeinbase(a, 2);
}

static int count_lsb_bits(void *a)
{
   LTC_ARGCHK(a != NULL);
   return mpz_scan1(a, 0);
}


static int twoexpt(void *a, int n)
{
   LTC_ARGCHK(a != NULL);
   mpz_set_ui(a, 0);
   mpz_setbit(a, n);
   return CRYPT_OK;
}

/* ---- conversions ---- */

static const char rmap[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";

/* read ascii string */
static int read_radix(void *a, const char *b, int radix)
{
   int ret;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   if (radix == 64) {
      /* Sadly, GMP only supports radixes up to 62, but we need 64.
       * So, although this is not the most elegant or efficient way,
       * let's just convert the base 64 string (6 bits per digit) to
       * an octal string (3 bits per digit) that's twice as long. */
      char c, *tmp, *q;
      const char *p;
      int i;
      tmp = XMALLOC (1 + 2 * strlen (b));
      if (tmp == NULL) {
         return CRYPT_MEM;
      }
      p = b;
      q = tmp;
      while ((c = *p++) != 0) {
         for (i = 0; i < 64; i++) {
            if (c == rmap[i])
               break;
         }
         if (i == 64) {
            XFREE (tmp);
            /* printf ("c = '%c'\n", c); */
            return CRYPT_ERROR;
         }
         *q++ = '0' + (i / 8);
         *q++ = '0' + (i % 8);
      }
      *q = 0;
      ret = mpz_set_str(a, tmp, 8);
      /* printf ("ret = %d for '%s'\n", ret, tmp); */
      XFREE (tmp);
   } else {
      ret = mpz_set_str(a, b, radix);
   }
   return (ret == 0 ? CRYPT_OK : CRYPT_ERROR);
}

/* write one */
static int write_radix(void *a, char *b, int radix)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   if (radix >= 11 && radix <= 36)
      /* If radix is positive, GMP uses lowercase, and if negative, uppercase.
       * We want it to use uppercase, to match the test vectors (presumably
       * generated with LibTomMath). */
      radix = -radix;
   mpz_get_str(b, radix, a);
   return CRYPT_OK;
}

/* get size as unsigned char string */
static unsigned long unsigned_size(void *a)
{
   unsigned long t;
   LTC_ARGCHK(a != NULL);
   t = mpz_sizeinbase(a, 2);
   if (mpz_cmp_ui(((__mpz_struct *)a), 0) == 0) return 0;
   return (t>>3) + ((t&7)?1:0);
}

/* store */
static int unsigned_write(void *a, unsigned char *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_export(b, NULL, 1, 1, 1, 0, ((__mpz_struct*)a));
   return CRYPT_OK;
}

/* read */
static int unsigned_read(void *a, unsigned char *b, unsigned long len)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_import(a, len, 1, 1, 1, 0, b);
   return CRYPT_OK;
}

/* add */
static int add(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_add(c, a, b);
   return CRYPT_OK;
}

static int addi(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_add_ui(c, a, b);
   return CRYPT_OK;
}

/* sub */
static int sub(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_sub(c, a, b);
   return CRYPT_OK;
}

static int subi(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_sub_ui(c, a, b);
   return CRYPT_OK;
}

/* mul */
static int mul(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_mul(c, a, b);
   return CRYPT_OK;
}

static int muli(void *a, ltc_mp_digit b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_mul_ui(c, a, b);
   return CRYPT_OK;
}

/* sqr */
static int sqr(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_mul(b, a, a);
   return CRYPT_OK;
}

/* sqrtmod_prime */
static int sqrtmod_prime(void *n, void *prime, void *ret)
{
   int res, legendre, i;
   mpz_t t1, C, Q, S, Z, M, T, R, two;

   LTC_ARGCHK(n     != NULL);
   LTC_ARGCHK(prime != NULL);
   LTC_ARGCHK(ret   != NULL);

   /* first handle the simple cases */
   if (mpz_cmp_ui(((__mpz_struct *)n), 0) == 0) {
      mpz_set_ui(ret, 0);
      return CRYPT_OK;
   }
   if (mpz_cmp_ui(((__mpz_struct *)prime), 2) == 0)     return CRYPT_ERROR; /* prime must be odd */
   legendre = mpz_legendre(n, prime);
   if (legendre == -1)                                  return CRYPT_ERROR; /* quadratic non-residue mod prime */

   mpz_init(t1); mpz_init(C); mpz_init(Q);
   mpz_init(S);  mpz_init(Z); mpz_init(M);
   mpz_init(T);  mpz_init(R); mpz_init(two);

   /* SPECIAL CASE: if prime mod 4 == 3
    * compute directly: res = n^(prime+1)/4 mod prime
    * Handbook of Applied Cryptography algorithm 3.36
    */
   i = mpz_mod_ui(t1, prime, 4); /* t1 is ignored here */
   if (i == 3) {
      mpz_add_ui(t1, prime, 1);
      mpz_fdiv_q_2exp(t1, t1, 2);
      mpz_powm(ret, n, t1, prime);
      res = CRYPT_OK;
      goto cleanup;
   }

   /* NOW: Tonelli-Shanks algorithm */

   /* factor out powers of 2 from prime-1, defining Q and S as: prime-1 = Q*2^S */
   mpz_set(Q, prime);
   mpz_sub_ui(Q, Q, 1);
   /* Q = prime - 1 */
   mpz_set_ui(S, 0);
   /* S = 0 */
   while (mpz_even_p(Q)) {
      mpz_fdiv_q_2exp(Q, Q, 1);
      /* Q = Q / 2 */
      mpz_add_ui(S, S, 1);
      /* S = S + 1 */
   }

   /* find a Z such that the Legendre symbol (Z|prime) == -1 */
   mpz_set_ui(Z, 2);
   /* Z = 2 */
   while(1) {
      legendre = mpz_legendre(Z, prime);
      if (legendre == -1) break;
      mpz_add_ui(Z, Z, 1);
      /* Z = Z + 1 */
   }

   mpz_powm(C, Z, Q, prime);
   /* C = Z ^ Q mod prime */
   mpz_add_ui(t1, Q, 1);
   mpz_fdiv_q_2exp(t1, t1, 1);
   /* t1 = (Q + 1) / 2 */
   mpz_powm(R, n, t1, prime);
   /* R = n ^ ((Q + 1) / 2) mod prime */
   mpz_powm(T, n, Q, prime);
   /* T = n ^ Q mod prime */
   mpz_set(M, S);
   /* M = S */
   mpz_set_ui(two, 2);

   while (1) {
      mpz_set(t1, T);
      i = 0;
      while (1) {
         if (mpz_cmp_ui(((__mpz_struct *)t1), 1) == 0) break;
         mpz_powm(t1, t1, two, prime);
         i++;
      }
      if (i == 0) {
         mpz_set(ret, R);
         res = CRYPT_OK;
         goto cleanup;
      }
      mpz_sub_ui(t1, M, i);
      mpz_sub_ui(t1, t1, 1);
      mpz_powm(t1, two, t1, prime);
      /* t1 = 2 ^ (M - i - 1) */
      mpz_powm(t1, C, t1, prime);
      /* t1 = C ^ (2 ^ (M - i - 1)) mod prime */
      mpz_mul(C, t1, t1);
      mpz_mod(C, C, prime);
      /* C = (t1 * t1) mod prime */
      mpz_mul(R, R, t1);
      mpz_mod(R, R, prime);
      /* R = (R * t1) mod prime */
      mpz_mul(T, T, C);
      mpz_mod(T, T, prime);
      /* T = (T * C) mod prime */
      mpz_set_ui(M, i);
      /* M = i */
   }

cleanup:
   mpz_clear(t1); mpz_clear(C); mpz_clear(Q);
   mpz_clear(S);  mpz_clear(Z); mpz_clear(M);
   mpz_clear(T);  mpz_clear(R); mpz_clear(two);
   return res;
}

/* div */
static int divide(void *a, void *b, void *c, void *d)
{
   mpz_t tmp;
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   if (c != NULL) {
      mpz_init(tmp);
      mpz_divexact(tmp, a, b);
   }
   if (d != NULL) {
      mpz_mod(d, a, b);
   }
   if (c != NULL) {
      mpz_set(c, tmp);
      mpz_clear(tmp);
   }
   return CRYPT_OK;
}

static int div_2(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_divexact_ui(b, a, 2);
   return CRYPT_OK;
}

/* modi */
static int modi(void *a, ltc_mp_digit b, ltc_mp_digit *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);

   *c = mpz_fdiv_ui(a, b);
   return CRYPT_OK;
}

/* gcd */
static int gcd(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_gcd(c, a, b);
   return CRYPT_OK;
}

/* lcm */
static int lcm(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_lcm(c, a, b);
   return CRYPT_OK;
}

static int addmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   mpz_add(d, a, b);
   mpz_mod(d, d, c);
   return CRYPT_OK;
}

static int submod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   mpz_sub(d, a, b);
   mpz_mod(d, d, c);
   return CRYPT_OK;
}

static int mulmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   mpz_mul(d, a, b);
   mpz_mod(d, d, c);
   return CRYPT_OK;
}

static int sqrmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_mul(c, a, a);
   mpz_mod(c, c, b);
   return CRYPT_OK;
}

/* invmod */
static int invmod(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_invert(c, a, b);
   return CRYPT_OK;
}

/* setup */
static int montgomery_setup(void *a, void **b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   *b = (void *)1;
   return CRYPT_OK;
}

/* get normalization value */
static int montgomery_normalization(void *a, void *b)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   mpz_set_ui(a, 1);
   return CRYPT_OK;
}

/* reduce */
static int montgomery_reduce(void *a, void *b, void *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   mpz_mod(a, a, b);
   return CRYPT_OK;
}

/* clean up */
static void montgomery_deinit(void *a)
{
  LTC_UNUSED_PARAM(a);
}

static int exptmod(void *a, void *b, void *c, void *d)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(b != NULL);
   LTC_ARGCHK(c != NULL);
   LTC_ARGCHK(d != NULL);
   mpz_powm(d, a, b, c);
   return CRYPT_OK;
}

static int isprime(void *a, int b, int *c)
{
   LTC_ARGCHK(a != NULL);
   LTC_ARGCHK(c != NULL);
   if (b == 0) {
       b = LTC_MILLER_RABIN_REPS;
   } /* if */
   *c = mpz_probab_prime_p(a, b) > 0 ? LTC_MP_YES : LTC_MP_NO;
   return CRYPT_OK;
}

static int set_rand(void *a, int size)
{
   LTC_ARGCHK(a != NULL);
   mpz_random(a, size);
   return CRYPT_OK;
}

const ltc_math_descriptor gmp_desc = {
   "GNU MP",
   sizeof(mp_limb_t) * CHAR_BIT - GMP_NAIL_BITS,

   &init,
   &init_copy,
   &deinit,

   &neg,
   &copy,

   &set_int,
   &get_int,
   &get_digit,
   &get_digit_count,
   &compare,
   &compare_d,
   &count_bits,
   &count_lsb_bits,
   &twoexpt,

   &read_radix,
   &write_radix,
   &unsigned_size,
   &unsigned_write,
   &unsigned_read,

   &add,
   &addi,
   &sub,
   &subi,
   &mul,
   &muli,
   &sqr,
   &sqrtmod_prime,
   &divide,
   &div_2,
   &modi,
   &gcd,
   &lcm,

   &mulmod,
   &sqrmod,
   &invmod,

   &montgomery_setup,
   &montgomery_normalization,
   &montgomery_reduce,
   &montgomery_deinit,

   &exptmod,
   &isprime,

#ifdef LTC_MECC
#ifdef LTC_MECC_FP
   &ltc_ecc_fp_mulmod,
#else
   &ltc_ecc_mulmod,
#endif /* LTC_MECC_FP */
   &ltc_ecc_projective_add_point,
   &ltc_ecc_projective_dbl_point,
   &ltc_ecc_map,
#ifdef LTC_ECC_SHAMIR
#ifdef LTC_MECC_FP
   &ltc_ecc_fp_mul2add,
#else
   &ltc_ecc_mul2add,
#endif /* LTC_MECC_FP */
#else
   NULL,
#endif /* LTC_ECC_SHAMIR */
#else
   NULL, NULL, NULL, NULL, NULL,
#endif /* LTC_MECC */

#ifdef LTC_MRSA
   &rsa_make_key,
   &rsa_exptmod,
#else
   NULL, NULL,
#endif
   &addmod,
   &submod,

   &set_rand,

};


#endif

/* ref:         HEAD -> develop */
/* git commit:  9c0d7085234bd6baba2ab8fd9eee62254599341c */
/* commit time: 2018-10-15 10:51:17 +0200 */
