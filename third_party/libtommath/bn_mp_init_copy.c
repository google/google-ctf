#include "tommath_private.h"
#ifdef BN_MP_INIT_COPY_C
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

/* creates "a" then copies b into it */
int mp_init_copy(mp_int *a, const mp_int *b)
{
   int     res;

   if ((res = mp_init_size(a, b->used)) != MP_OKAY) {
      return res;
   }

   if ((res = mp_copy(b, a)) != MP_OKAY) {
      mp_clear(a);
   }

   return res;
}
#endif

/* ref:         HEAD -> develop */
/* git commit:  8b9f98baa16b21e1612ac6746273febb74150a6f */
/* commit time: 2018-09-23 21:37:58 +0200 */
