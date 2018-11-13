#include "tommath_private.h"
#ifdef BN_MP_OR_C
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

/* OR two ints together */
int mp_or(const mp_int *a, const mp_int *b, mp_int *c)
{
   int     res, ix, px;
   mp_int  t;
   const mp_int *x;

   if (a->used > b->used) {
      if ((res = mp_init_copy(&t, a)) != MP_OKAY) {
         return res;
      }
      px = b->used;
      x = b;
   } else {
      if ((res = mp_init_copy(&t, b)) != MP_OKAY) {
         return res;
      }
      px = a->used;
      x = a;
   }

   for (ix = 0; ix < px; ix++) {
      t.dp[ix] |= x->dp[ix];
   }
   mp_clamp(&t);
   mp_exch(c, &t);
   mp_clear(&t);
   return MP_OKAY;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
