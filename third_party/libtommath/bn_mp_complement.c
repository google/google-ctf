#include "tommath_private.h"
#ifdef BN_MP_COMPLEMENT_C
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

/* b = ~a */
int mp_complement(const mp_int *a, mp_int *b)
{
   int res = mp_neg(a, b);
   return (res == MP_OKAY) ? mp_sub_d(b, 1uL, b) : res;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
