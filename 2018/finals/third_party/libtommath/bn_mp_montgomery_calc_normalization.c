#include "tommath_private.h"
#ifdef BN_MP_MONTGOMERY_CALC_NORMALIZATION_C
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

/*
 * shifts with subtractions when the result is greater than b.
 *
 * The method is slightly modified to shift B unconditionally upto just under
 * the leading bit of b.  This saves alot of multiple precision shifting.
 */
int mp_montgomery_calc_normalization(mp_int *a, const mp_int *b)
{
   int     x, bits, res;

   /* how many bits of last digit does b use */
   bits = mp_count_bits(b) % DIGIT_BIT;

   if (b->used > 1) {
      if ((res = mp_2expt(a, ((b->used - 1) * DIGIT_BIT) + bits - 1)) != MP_OKAY) {
         return res;
      }
   } else {
      mp_set(a, 1uL);
      bits = 1;
   }


   /* now compute C = A * B mod b */
   for (x = bits - 1; x < (int)DIGIT_BIT; x++) {
      if ((res = mp_mul_2(a, a)) != MP_OKAY) {
         return res;
      }
      if (mp_cmp_mag(a, b) != MP_LT) {
         if ((res = s_mp_sub(a, b, a)) != MP_OKAY) {
            return res;
         }
      }
   }

   return MP_OKAY;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
