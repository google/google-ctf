#include "tommath_private.h"
#ifdef BN_MP_JACOBI_C
/* LibTomMath, multiple-precision integer library -- Tom St Denis
 *
 * LibTomMath is a library that provides multiple-precision
 * integer arithmetic as well as number theoretic functionality.
 *
 * The library was designed directly after the MPI library by
 * Michael Fromberger but has been written from scratch with
 * additional optimizations in place.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */

/* computes the jacobi c = (a | n) (or Legendre if n is prime)
 * HAC pp. 73 Algorithm 2.149
 * HAC is wrong here, as the special case of (0 | 1) is not
 * handled correctly.
 */
int mp_jacobi(const mp_int *a, const mp_int *n, int *c)
{
   mp_int  a1, p1;
   int     k, s, r, res;
   mp_digit residue;

   /* if a < 0 return MP_VAL */
   if (mp_isneg(a) == MP_YES) {
      return MP_VAL;
   }

   /* if n <= 0 return MP_VAL */
   if (mp_cmp_d(n, 0uL) != MP_GT) {
      return MP_VAL;
   }

   /* step 1. handle case of a == 0 */
   if (mp_iszero(a) == MP_YES) {
      /* special case of a == 0 and n == 1 */
      if (mp_cmp_d(n, 1uL) == MP_EQ) {
         *c = 1;
      } else {
         *c = 0;
      }
      return MP_OKAY;
   }

   /* step 2.  if a == 1, return 1 */
   if (mp_cmp_d(a, 1uL) == MP_EQ) {
      *c = 1;
      return MP_OKAY;
   }

   /* default */
   s = 0;

   /* step 3.  write a = a1 * 2**k  */
   if ((res = mp_init_copy(&a1, a)) != MP_OKAY) {
      return res;
   }

   if ((res = mp_init(&p1)) != MP_OKAY) {
      goto LBL_A1;
   }

   /* divide out larger power of two */
   k = mp_cnt_lsb(&a1);
   if ((res = mp_div_2d(&a1, k, &a1, NULL)) != MP_OKAY) {
      goto LBL_P1;
   }

   /* step 4.  if e is even set s=1 */
   if (((unsigned)k & 1u) == 0u) {
      s = 1;
   } else {
      /* else set s=1 if p = 1/7 (mod 8) or s=-1 if p = 3/5 (mod 8) */
      residue = n->dp[0] & 7u;

      if ((residue == 1u) || (residue == 7u)) {
         s = 1;
      } else if ((residue == 3u) || (residue == 5u)) {
         s = -1;
      }
   }

   /* step 5.  if p == 3 (mod 4) *and* a1 == 3 (mod 4) then s = -s */
   if (((n->dp[0] & 3u) == 3u) && ((a1.dp[0] & 3u) == 3u)) {
      s = -s;
   }

   /* if a1 == 1 we're done */
   if (mp_cmp_d(&a1, 1uL) == MP_EQ) {
      *c = s;
   } else {
      /* n1 = n mod a1 */
      if ((res = mp_mod(n, &a1, &p1)) != MP_OKAY) {
         goto LBL_P1;
      }
      if ((res = mp_jacobi(&p1, &a1, &r)) != MP_OKAY) {
         goto LBL_P1;
      }
      *c = s * r;
   }

   /* done */
   res = MP_OKAY;
LBL_P1:
   mp_clear(&p1);
LBL_A1:
   mp_clear(&a1);
   return res;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
