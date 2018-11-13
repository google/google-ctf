#include "tommath_private.h"
#ifdef BN_MP_INVMOD_C
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

/* hac 14.61, pp608 */
int mp_invmod(const mp_int *a, const mp_int *b, mp_int *c)
{
   /* b cannot be negative and has to be >1 */
   if ((b->sign == MP_NEG) || (mp_cmp_d(b, 1uL) != MP_GT)) {
      return MP_VAL;
   }

#ifdef BN_FAST_MP_INVMOD_C
   /* if the modulus is odd we can use a faster routine instead */
   if ((mp_isodd(b) == MP_YES)) {
      return fast_mp_invmod(a, b, c);
   }
#endif

#ifdef BN_MP_INVMOD_SLOW_C
   return mp_invmod_slow(a, b, c);
#else
   return MP_VAL;
#endif
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
