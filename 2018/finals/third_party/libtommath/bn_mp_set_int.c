#include "tommath_private.h"
#ifdef BN_MP_SET_INT_C
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

/* set a 32-bit const */
int mp_set_int(mp_int *a, unsigned long b)
{
   int     x, res;

   mp_zero(a);

   /* set four bits at a time */
   for (x = 0; x < 8; x++) {
      /* shift the number up four bits */
      if ((res = mp_mul_2d(a, 4, a)) != MP_OKAY) {
         return res;
      }

      /* OR in the top four bits of the source */
      a->dp[0] |= (mp_digit)(b >> 28) & 15uL;

      /* shift the source up to the next four bits */
      b <<= 4;

      /* ensure that digits are not clamped off */
      a->used += 1;
   }
   mp_clamp(a);
   return MP_OKAY;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
