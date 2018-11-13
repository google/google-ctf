#include "tommath_private.h"
#ifdef BN_MP_COPY_C
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

/* copy, b = a */
int mp_copy(const mp_int *a, mp_int *b)
{
   int     res, n;

   /* if dst == src do nothing */
   if (a == b) {
      return MP_OKAY;
   }

   /* grow dest */
   if (b->alloc < a->used) {
      if ((res = mp_grow(b, a->used)) != MP_OKAY) {
         return res;
      }
   }

   /* zero b and copy the parameters over */
   {
      mp_digit *tmpa, *tmpb;

      /* pointer aliases */

      /* source */
      tmpa = a->dp;

      /* destination */
      tmpb = b->dp;

      /* copy all the digits */
      for (n = 0; n < a->used; n++) {
         *tmpb++ = *tmpa++;
      }

      /* clear high digits */
      for (; n < b->used; n++) {
         *tmpb++ = 0;
      }
   }

   /* copy used count and sign */
   b->used = a->used;
   b->sign = a->sign;
   return MP_OKAY;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
