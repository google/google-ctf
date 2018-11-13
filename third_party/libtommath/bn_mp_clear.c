#include "tommath_private.h"
#ifdef BN_MP_CLEAR_C
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

/* clear one (frees)  */
void mp_clear(mp_int *a)
{
   int i;

   /* only do anything if a hasn't been freed previously */
   if (a->dp != NULL) {
      /* first zero the digits */
      for (i = 0; i < a->used; i++) {
         a->dp[i] = 0;
      }

      /* free ram */
      XFREE(a->dp);

      /* reset members to make debugging easier */
      a->dp    = NULL;
      a->alloc = a->used = 0;
      a->sign  = MP_ZPOS;
   }
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
