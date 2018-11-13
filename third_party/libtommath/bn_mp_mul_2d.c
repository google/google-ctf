#include "tommath_private.h"
#ifdef BN_MP_MUL_2D_C
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

/* shift left by a certain bit count */
int mp_mul_2d(const mp_int *a, int b, mp_int *c)
{
   mp_digit d;
   int      res;

   /* copy */
   if (a != c) {
      if ((res = mp_copy(a, c)) != MP_OKAY) {
         return res;
      }
   }

   if (c->alloc < (c->used + (b / DIGIT_BIT) + 1)) {
      if ((res = mp_grow(c, c->used + (b / DIGIT_BIT) + 1)) != MP_OKAY) {
         return res;
      }
   }

   /* shift by as many digits in the bit count */
   if (b >= DIGIT_BIT) {
      if ((res = mp_lshd(c, b / DIGIT_BIT)) != MP_OKAY) {
         return res;
      }
   }

   /* shift any bit count < DIGIT_BIT */
   d = (mp_digit)(b % DIGIT_BIT);
   if (d != 0u) {
      mp_digit *tmpc, shift, mask, r, rr;
      int x;

      /* bitmask for carries */
      mask = ((mp_digit)1 << d) - (mp_digit)1;

      /* shift for msbs */
      shift = (mp_digit)DIGIT_BIT - d;

      /* alias */
      tmpc = c->dp;

      /* carry */
      r    = 0;
      for (x = 0; x < c->used; x++) {
         /* get the higher bits of the current word */
         rr = (*tmpc >> shift) & mask;

         /* shift the current word and OR in the carry */
         *tmpc = ((*tmpc << d) | r) & MP_MASK;
         ++tmpc;

         /* set the carry to the carry bits of the current word */
         r = rr;
      }

      /* set final carry */
      if (r != 0u) {
         c->dp[(c->used)++] = r;
      }
   }
   mp_clamp(c);
   return MP_OKAY;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
