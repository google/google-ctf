#include "tommath_private.h"
#ifdef BN_MP_SET_C
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

/* set to a digit */
void mp_set(mp_int *a, mp_digit b)
{
   mp_zero(a);
   a->dp[0] = b & MP_MASK;
   a->used  = (a->dp[0] != 0u) ? 1 : 0;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
